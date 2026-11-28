//! The channel setup on the node's surface: asking a sender for a channel
//! (docs/specs/channel.md, Setup) and signing the one Interest the node signs for it.

use bytes::Bytes;
use ndn_foundation_types::Name;

use super::error::ChanError;
use super::sessions::ChannelInfo;
use super::wire::ChannelMode;
use crate::error::HeapError;
use crate::host::NodeHandle;
use crate::wire::{parse_chan_prefix, parse_query_prefix};

impl NodeHandle {
    /// Ask the device `device` for its **`Latest`** channel over `space` and hold the session it
    /// answers with: what a host does that wants live data from one sender it knows. The ask is a
    /// signed Interest `<device>/32=chan/<digest>`; the answer is judged as the setup says
    /// (docs/specs/channel.md): the Data is the device's, the device is a **writer** of the space
    /// now, a sealed space's epoch is the one in force here, and the key opens under this device's
    /// recipient secret. Asking again renews the session held (the same channel id, a new key and
    /// lifetime). A session is renewed by the node at 75 % of its lifetime and is dropped, with its
    /// reason, when the sender no longer stands.
    ///
    /// # Errors
    ///
    /// Each [`ChanError`] says why and, by [`ChanError::next`], what to do:
    /// [`ChanError::BadName`] (fix the name), [`ChanError::NotReady`] (the space is not open here
    /// or its record not held: retry), [`ChanError::NotAllowed`] (this device is no member: ask the
    /// owner), [`ChanError::NotAnswered`], [`ChanError::Unreachable`], [`ChanError::Busy`] (retry),
    /// [`ChanError::Refused`] (the sender's own words), [`ChanError::SenderNotWriter`] (ask a
    /// writer's device), [`ChanError::BadAnswer`] (retry), [`ChanError::Superseded`] (the last
    /// `Items` of the channel was dropped while the ask was on its way: ask again if a stream
    /// still wants it), [`ChanError::Local`] (fix this device).
    pub async fn ask_channel(&self, space: &Name, device: &Name) -> Result<ChannelInfo, ChanError> {
        self.ask_channel_in(space, device, ChannelMode::Latest)
            .await
    }

    /// [`Self::ask_channel`] for a channel of `mode`.
    ///
    /// With [`ChannelMode::Ask`] the session carries no emission: it gives this device and the
    /// server a **pair** of keys that seal the `QUERY` and `ANSWER` frames of queries
    /// ([`QueryPath::Channel`](crate::QueryPath::Channel); [`QueryPath::Auto`](crate::QueryPath::Auto)
    /// takes the channel for a server whose `Ask` session is held). A `Channel` query makes the
    /// session itself, so this is for an application that wants it warm before its first `Auto`
    /// query. The session is kept while queries use it, and let go (with an `Unsub`) after a minute
    /// with none, or after three queries in a row that the server never answered: asking again
    /// makes a new one. The errors are those of [`Self::ask_channel`].
    pub async fn ask_channel_in(
        &self,
        space: &Name,
        device: &Name,
        mode: ChannelMode,
    ) -> Result<ChannelInfo, ChanError> {
        let session = self.inner.chan_ask(space, device, mode).await?;
        Ok(session.info())
    }

    /// Sign the Interest of a channel's ask or of a query: `prefix` is `<device>/32=chan` and
    /// `parameters` a `CHAN_ASK` (the ask `<device>/32=chan/<digest>`, InterestLifetime 4 s), or
    /// `prefix` is `<device>/32=query` and `parameters` a `QUERY_ASK` (the query
    /// `<device>/32=query/<digest>`, InterestLifetime the query's own deadline). Either way:
    /// an InterestSignatureInfo with this device's key as the KeyLocator, a SignatureNonce and a
    /// SignatureTime, MustBeFresh. The node signs no other Interest, since a signed Interest of
    /// the device's key is a command wherever the key is trusted: `parameters` must decode as
    /// the record the name says, and `device` may not lie under `/localhost` or `/localhop`.
    ///
    /// # Errors
    ///
    /// [`HeapError::BadRequest`] when `prefix` is neither `<device>/32=chan` nor
    /// `<device>/32=query`, `device` is under a reserved prefix, or `parameters` are not the
    /// record that name takes (a `CHAN_ASK`, a `QUERY_ASK`);
    /// [`HeapError::Local`] when the key does not sign synchronously.
    pub fn sign_interest(&self, prefix: &Name, parameters: &[u8]) -> Result<Bytes, HeapError> {
        if let Some(device) = parse_chan_prefix(prefix) {
            return self.inner.sign_ask(&device, parameters);
        }
        if let Some(device) = parse_query_prefix(prefix) {
            return self.inner.sign_query(&device, parameters);
        }
        Err(HeapError::BadRequest {
            why: format!(
                "{prefix} is not a name this node signs an Interest for: only \
                 `<device>/32=chan` (the ask of a channel) and `<device>/32=query` (a query)"
            ),
        })
    }
}
