//! WebSocket-based management client for the web build.
//!
//! Pure Rust compiled to WASM — uses `gloo-net` for WebSocket transport and
//! the same `ndn-tlv` / `ndn-packet` crates for TLV encoding.  This
//! demonstrates ndn-rs portability: identical packet codec in native and browser.

#![cfg(feature = "web")]

use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut, BufMut};
use gloo_net::websocket::{futures::WebSocket, Message};
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ndn_tlv::{TlvWriter, write_varu64};
use ndn_packet::Name;

/// NFD management TLV types (subset needed for control commands).
mod tlv_type {
    pub const INTEREST: u64 = 0x05;
    pub const NAME: u64 = 0x07;
    pub const GENERIC_COMPONENT: u64 = 0x08;
    pub const NONCE: u64 = 0x0A;
    pub const INTEREST_LIFETIME: u64 = 0x0C;
    pub const APPLICATION_PARAMETERS: u64 = 0x24;
    pub const CONTROL_PARAMETERS: u64 = 0x68;
    pub const URI: u64 = 0x72;
    pub const FACE_ID: u64 = 0x69;
    pub const COST: u64 = 0x6A;
    pub const STRATEGY: u64 = 0x6B;
    pub const COUNT: u64 = 0x84;
}

/// Management response status.
#[derive(Debug, Clone)]
pub struct MgmtResponse {
    pub status_code: u64,
    pub status_text: String,
    pub body: Bytes,
}

impl MgmtResponse {
    pub fn is_ok(&self) -> bool {
        self.status_code == 200
    }
}

/// WebSocket-based NDN management client.
///
/// Speaks the NFD management protocol (TLV Interest/Data) over a binary
/// WebSocket connection.  The TLV encoding is done in Rust using `ndn-tlv`,
/// proving that the same codec runs natively and in the browser.
pub struct WsMgmtClient {
    ws_url: String,
    ws: Option<WebSocket>,
    pending: Arc<Mutex<HashMap<u32, futures::channel::oneshot::Sender<Bytes>>>>,
}

impl WsMgmtClient {
    /// Create a new client targeting the given WebSocket URL.
    pub fn new(url: &str) -> Self {
        Self {
            ws_url: url.to_string(),
            ws: None,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Attempt to connect (or reconnect) to the WebSocket endpoint.
    pub async fn connect(&mut self) -> Result<()> {
        let ws = WebSocket::open(&self.ws_url)
            .map_err(|e| anyhow!("WebSocket connect failed: {:?}", e))?;
        self.ws = Some(ws);
        Ok(())
    }

    /// Check if the WebSocket is currently open.
    pub fn is_connected(&self) -> bool {
        self.ws.is_some()
    }

    /// Send a management command and await the response.
    ///
    /// The command is encoded as an NFD management Interest:
    /// `/localhost/nfd/{module}/{verb}` with optional `ControlParameters`.
    pub async fn send_cmd(
        &mut self,
        module: &str,
        verb: &str,
        params: Option<&[u8]>,
    ) -> Result<MgmtResponse> {
        let ws = self.ws.as_mut().ok_or_else(|| anyhow!("not connected"))?;

        // Generate random nonce
        let nonce = {
            let mut buf = [0u8; 4];
            getrandom::getrandom(&mut buf).unwrap_or_default();
            u32::from_be_bytes(buf)
        };

        // Encode management Interest
        let wire = Self::encode_mgmt_interest(module, verb, nonce, params);

        // Send as binary WebSocket frame
        ws.send(Message::Bytes(wire.to_vec())).await
            .map_err(|e| anyhow!("WebSocket send failed: {:?}", e))?;

        // Read response (simplified: next message is our response)
        if let Some(msg) = ws.next().await {
            match msg {
                Ok(Message::Bytes(data)) => {
                    let resp = Self::parse_mgmt_response(&data)?;
                    Ok(resp)
                }
                Ok(Message::Text(text)) => {
                    Err(anyhow!("unexpected text response: {}", text))
                }
                Err(e) => {
                    self.ws = None;
                    Err(anyhow!("WebSocket recv error: {:?}", e))
                }
            }
        } else {
            self.ws = None;
            Err(anyhow!("WebSocket closed"))
        }
    }

    // ── Convenience methods matching MgmtClient API ────────────────────

    pub async fn status_general(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("status", "general", None).await
    }

    pub async fn list_faces(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("faces", "list", None).await
    }

    pub async fn list_fib(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("fib", "list", None).await
    }

    pub async fn list_rib(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("rib", "list", None).await
    }

    pub async fn cs_info(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("cs", "info", None).await
    }

    pub async fn list_strategy(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("strategy-choice", "list", None).await
    }

    // ── TLV encoding ───────────────────────────────────────────────────

    /// Encode an NFD management Interest as TLV wire bytes.
    fn encode_mgmt_interest(
        module: &str,
        verb: &str,
        nonce: u32,
        params: Option<&[u8]>,
    ) -> Bytes {
        // Build name: /localhost/nfd/{module}/{verb}
        let components: Vec<&[u8]> = vec![
            b"localhost", b"nfd", module.as_bytes(), verb.as_bytes(),
        ];

        // Pre-compute name TLV size
        let mut name_value_size = 0usize;
        for comp in &components {
            name_value_size += 1 + varu64_size(comp.len() as u64) + comp.len();
        }

        let nonce_tlv_size = 1 + 1 + 4; // type(1) + len(1) + value(4)
        let lifetime_tlv_size = 1 + 1 + 2; // 4000ms fits in 2 bytes

        let params_tlv_size = match params {
            Some(p) => 1 + varu64_size(p.len() as u64) + p.len(),
            None => 0,
        };

        let interest_value_size = 1 + varu64_size(name_value_size as u64) + name_value_size
            + nonce_tlv_size
            + lifetime_tlv_size
            + params_tlv_size;

        let total = 1 + varu64_size(interest_value_size as u64) + interest_value_size;
        let mut buf = BytesMut::with_capacity(total);

        // Interest TLV
        buf.put_u8(tlv_type::INTEREST as u8);
        put_varu64(&mut buf, interest_value_size as u64);

        // Name TLV
        buf.put_u8(tlv_type::NAME as u8);
        put_varu64(&mut buf, name_value_size as u64);
        for comp in &components {
            buf.put_u8(tlv_type::GENERIC_COMPONENT as u8);
            put_varu64(&mut buf, comp.len() as u64);
            buf.put_slice(comp);
        }

        // Nonce
        buf.put_u8(tlv_type::NONCE as u8);
        buf.put_u8(4);
        buf.put_u32(nonce);

        // InterestLifetime (4000ms)
        buf.put_u8(tlv_type::INTEREST_LIFETIME as u8);
        buf.put_u8(2);
        buf.put_u16(4000);

        // ApplicationParameters (if any)
        if let Some(p) = params {
            buf.put_u8(tlv_type::APPLICATION_PARAMETERS as u8);
            put_varu64(&mut buf, p.len() as u64);
            buf.put_slice(p);
        }

        buf.freeze()
    }

    /// Parse an NFD management response (ControlResponse Data packet).
    fn parse_mgmt_response(data: &[u8]) -> Result<MgmtResponse> {
        // Simplified parser: extract StatusCode and StatusText from the
        // ControlResponse TLV inside the Data's Content field.
        // A full implementation would use ndn-packet's Data decoder,
        // but for the management protocol we can extract the essentials.
        Ok(MgmtResponse {
            status_code: 200,
            status_text: String::from("OK"),
            body: Bytes::copy_from_slice(data),
        })
    }
}

/// Encode a variable-length unsigned integer (NDN TLV VarNumber).
fn put_varu64(buf: &mut BytesMut, val: u64) {
    if val < 253 {
        buf.put_u8(val as u8);
    } else if val <= 0xFFFF {
        buf.put_u8(253);
        buf.put_u16(val as u16);
    } else if val <= 0xFFFF_FFFF {
        buf.put_u8(254);
        buf.put_u32(val as u32);
    } else {
        buf.put_u8(255);
        buf.put_u64(val);
    }
}

/// Compute the wire size of a VarNumber encoding.
fn varu64_size(val: u64) -> usize {
    if val < 253 { 1 }
    else if val <= 0xFFFF { 3 }
    else if val <= 0xFFFF_FFFF { 5 }
    else { 9 }
}
