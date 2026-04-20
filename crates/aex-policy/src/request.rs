use aex_core::AgentId;
use aex_scanner::PipelineVerdict;

/// Everything a [`crate::PolicyEngine`] needs to decide on a proposed
/// transfer.
///
/// Borrowed fields so the caller isn't forced to clone. The request lives
/// entirely inside one `evaluate` call.
pub struct PolicyRequest<'a> {
    pub sender: &'a AgentId,

    /// Recipient address as submitted by the sender. Format-agnostic at
    /// this layer: `spize:...`, `did:...`, email, phone. The routing layer
    /// has already parsed and classified it; the policy engine only uses
    /// the kind (see [`RecipientKind`]) for rules.
    pub recipient: &'a str,
    pub recipient_kind: RecipientKind,

    pub size_bytes: u64,
    pub declared_mime: Option<&'a str>,

    /// The org the sender belongs to (parsed from the agent_id).
    pub sender_org: &'a str,

    /// Scanner verdict. `None` before the pre-scan hook, `Some` after.
    pub scanner_verdict: Option<&'a PipelineVerdict>,
}

impl<'a> PolicyRequest<'a> {
    pub fn new(
        sender: &'a AgentId,
        sender_org: &'a str,
        recipient: &'a str,
        recipient_kind: RecipientKind,
        size_bytes: u64,
    ) -> Self {
        Self {
            sender,
            sender_org,
            recipient,
            recipient_kind,
            size_bytes,
            declared_mime: None,
            scanner_verdict: None,
        }
    }

    pub fn with_declared_mime(mut self, mime: &'a str) -> Self {
        self.declared_mime = Some(mime);
        self
    }

    pub fn with_verdict(mut self, verdict: &'a PipelineVerdict) -> Self {
        self.scanner_verdict = Some(verdict);
        self
    }
}

/// Coarse classification of the recipient address, so the policy engine
/// can apply rules like "no agent-to-human bridge for dev tier".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientKind {
    /// spize:org/name:fingerprint
    SpizeNative,
    /// did:ethr / did:web / did:key
    Did,
    /// Email / phone — Agent↔Human bridge mode.
    HumanBridge,
    Unknown,
}
