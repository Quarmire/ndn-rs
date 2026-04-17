use std::path::Path;
use std::time::Duration;

use bytes::Bytes;

use ndn_faces::local::InProcHandle;
use ndn_ipc::ForwarderClient;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, Name};
use ndn_security::{SafeData, ValidationResult, Validator};

use crate::AppError;
use crate::connection::NdnConnection;

/// Default Interest lifetime: 4 seconds.
pub const DEFAULT_INTEREST_LIFETIME: Duration = Duration::from_millis(4000);

/// Default local timeout for waiting on a response.
///
/// This is the local safety-net timeout independent of the Interest lifetime
/// sent on the wire. Set slightly longer than the default Interest lifetime
/// to account for forwarding and processing delays.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(4500);

/// High-level NDN consumer — fetches Data by name.
pub struct Consumer {
    conn: NdnConnection,
}

impl Consumer {
    /// Connect to an external router via its face socket.
    pub async fn connect(socket: impl AsRef<Path>) -> Result<Self, AppError> {
        let client = ForwarderClient::connect(socket)
            .await
            .map_err(AppError::Connection)?;
        Ok(Self {
            conn: NdnConnection::External(client),
        })
    }

    /// Create from an in-process InProcHandle (embedded engine).
    pub fn from_handle(handle: InProcHandle) -> Self {
        Self {
            conn: NdnConnection::Embedded(handle),
        }
    }

    /// Express an Interest by name and return the decoded Data.
    ///
    /// Uses [`DEFAULT_INTEREST_LIFETIME`] for the wire Interest and
    /// [`DEFAULT_TIMEOUT`] for the local wait. To set hop limit,
    /// application parameters, or forwarding hints, use
    /// [`fetch_with`](Self::fetch_with).
    pub async fn fetch(&mut self, name: impl Into<Name>) -> Result<Data, AppError> {
        let wire = InterestBuilder::new(name)
            .lifetime(DEFAULT_INTEREST_LIFETIME)
            .build();
        self.fetch_wire(wire, DEFAULT_TIMEOUT).await
    }

    /// Express an Interest built with [`InterestBuilder`] and return the decoded Data.
    ///
    /// The local wait timeout is derived from the builder's Interest lifetime
    /// (+ 500 ms forwarding buffer). This is the right method when you need
    /// hop limit, forwarding hints, or application parameters:
    ///
    /// ```no_run
    /// # async fn example(mut consumer: ndn_app::Consumer) -> anyhow::Result<()> {
    /// use ndn_packet::encode::InterestBuilder;
    ///
    /// // Hop limit: limit forwarding to 4 hops.
    /// let data = consumer.fetch_with(
    ///     InterestBuilder::new("/ndn/remote/data").hop_limit(4)
    /// ).await?;
    ///
    /// // Forwarding hint: reach a producer via a delegation prefix.
    /// let data = consumer.fetch_with(
    ///     InterestBuilder::new("/alice/files/photo.jpg")
    ///         .forwarding_hint(vec!["/campus/ndn-hub".parse()?])
    /// ).await?;
    ///
    /// // Application parameters: parameterised fetch (e.g. RPC / query).
    /// let data = consumer.fetch_with(
    ///     InterestBuilder::new("/service/query")
    ///         .app_parameters(b"filter=recent&limit=10")
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch_with(&mut self, builder: InterestBuilder) -> Result<Data, AppError> {
        let (wire, timeout) = builder.build_with_timeout();
        self.fetch_wire(wire, timeout).await
    }

    /// Express a pre-encoded Interest and return the decoded Data.
    ///
    /// `timeout` is the local wait duration — set this to at least the
    /// Interest lifetime encoded in `wire` to avoid timing out before the
    /// forwarder does.
    ///
    /// Returns [`AppError::Nacked`] if the forwarder responds with a Nack
    /// (e.g. no route to the name prefix).
    pub async fn fetch_wire(&mut self, wire: Bytes, timeout: Duration) -> Result<Data, AppError> {
        self.conn.send(wire).await?;

        let reply = tokio::time::timeout(timeout, self.conn.recv())
            .await
            .map_err(|_| AppError::Timeout)?
            .ok_or(AppError::Closed)?;

        if is_lp_packet(&reply)
            && let Ok(lp) = LpPacket::decode(reply.clone())
        {
            if let Some(reason) = lp.nack {
                return Err(AppError::Nacked { reason });
            }
            if let Some(fragment) = lp.fragment {
                return Data::decode(fragment).map_err(|e| AppError::Protocol(e.to_string()));
            }
        }

        Data::decode(reply).map_err(|e| AppError::Protocol(e.to_string()))
    }

    /// Fetch and verify against a `Validator`. Returns `SafeData` on success.
    pub async fn fetch_verified(
        &mut self,
        name: impl Into<Name>,
        validator: &Validator,
    ) -> Result<SafeData, AppError> {
        let data = self.fetch(name).await?;
        match validator.validate(&data).await {
            ValidationResult::Valid(safe) => Ok(*safe),
            ValidationResult::Invalid(e) => Err(AppError::Protocol(e.to_string())),
            ValidationResult::Pending => {
                Err(AppError::Protocol("certificate chain not resolved".into()))
            }
        }
    }

    pub async fn get(&mut self, name: impl Into<Name>) -> Result<Bytes, AppError> {
        let data = self.fetch(name).await?;
        data.content()
            .map(|b| Bytes::copy_from_slice(b))
            .ok_or_else(|| AppError::Protocol("Data has no content".into()))
    }

    /// Fetch multiple names sequentially and collect results.
    ///
    /// Each Interest is expressed in order; the result vector preserves the
    /// input order regardless of which fetches succeed or fail.
    ///
    /// # Note
    ///
    /// Fetches are sequential because a single [`NdnConnection`] cannot
    /// correlate concurrent Interests to their responses without PIT tokens.
    /// For true concurrent fetch, create multiple `Consumer` instances and
    /// use `tokio::join!`.
    pub async fn fetch_all(&mut self, names: &[Name]) -> Vec<Result<Data, AppError>> {
        let mut results = Vec::with_capacity(names.len());
        for name in names {
            results.push(self.fetch(name.clone()).await);
        }
        results
    }

    /// Fetch with exponential-backoff retry.
    ///
    /// On timeout or connection error, waits `base_delay`, then `2×base_delay`,
    /// etc., up to `max_attempts` total tries (including the first). Returns the
    /// last error if all attempts are exhausted.
    pub async fn fetch_with_retry(
        &mut self,
        name: impl Into<Name>,
        max_attempts: u32,
        base_delay: std::time::Duration,
    ) -> Result<Data, AppError> {
        let name = name.into();
        let mut delay = base_delay;
        let attempts = max_attempts.max(1);
        let mut last_err = AppError::Timeout;
        for attempt in 0..attempts {
            match self.fetch(name.clone()).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    last_err = e;
                    if attempt + 1 < attempts {
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                    }
                }
            }
        }
        Err(last_err)
    }

    /// Fetch a segmented object produced with [`Producer::publish_large`].
    ///
    /// Fetches `/prefix/0`, reads `FinalBlockId` to determine the total segment
    /// count, then fetches all remaining segments in order. Segments are
    /// reassembled into a single contiguous buffer.
    ///
    /// Segment names are generic NameComponents with ASCII-decimal indices
    /// (e.g. `/prefix/0`, `/prefix/1`, ...), matching the convention used by
    /// [`Producer::publish_large`].
    pub async fn fetch_segmented(&mut self, prefix: impl Into<Name>) -> Result<Bytes, AppError> {
        let prefix = prefix.into();

        let seg0_name = prefix.clone().append("0");
        let seg0 = self.fetch(seg0_name).await?;

        let last_seg = parse_final_block_id_seg(&seg0).unwrap_or(0);

        let seg0_content = seg0
            .content()
            .map(|b| Bytes::copy_from_slice(b))
            .unwrap_or_default();

        if last_seg == 0 {
            return Ok(seg0_content);
        }

        let mut chunks: Vec<Bytes> = Vec::with_capacity(last_seg + 1);
        chunks.push(seg0_content);
        for i in 1..=last_seg {
            let name = prefix.clone().append(i.to_string());
            let data = self.fetch(name).await?;
            chunks.push(
                data.content()
                    .map(|b| Bytes::copy_from_slice(b))
                    .unwrap_or_default(),
            );
        }

        let total: usize = chunks.iter().map(|c| c.len()).sum();
        let mut out = bytes::BytesMut::with_capacity(total);
        for chunk in chunks {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    /// Fetch and verify against a `Validator`. Returns `SafeData` on success.
    pub async fn get_verified(
        &mut self,
        name: impl Into<Name>,
        validator: &ndn_security::Validator,
    ) -> Result<ndn_security::SafeData, AppError> {
        self.fetch_verified(name, validator).await
    }
}

/// Parse the segment index from a Data packet's FinalBlockId field.
///
/// FinalBlockId encodes a NameComponent TLV. For the convention used by
/// [`Producer::publish_large`], the value is an ASCII-decimal string
/// inside a generic NameComponent (TLV type 0x08).
/// Returns `None` if the field is absent or cannot be parsed.
fn parse_final_block_id_seg(data: &Data) -> Option<usize> {
    let meta = data.meta_info()?;
    let fbi = meta.final_block_id.as_ref()?;

    // FinalBlockId bytes = one NameComponent TLV: type(1-3B) + len(1-3B) + value.
    // Skip the type byte(s) and length byte(s) to reach the value bytes.
    // For short components (< 253 bytes), both type and length fit in one byte each.
    // type 0x08 (< 0xFD) = 1 byte; length < 253 = 1 byte.
    if fbi.len() < 2 {
        return None;
    }
    // First byte is the TLV type; second is the length (for short components).
    let len = fbi[1] as usize;
    let value_start = 2;
    if fbi.len() < value_start + len {
        return None;
    }
    let value = &fbi[value_start..value_start + len];
    std::str::from_utf8(value).ok()?.parse::<usize>().ok()
}
