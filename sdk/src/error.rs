// ============================================================================
// error.rs — typed error surface for the voting SDK
// ============================================================================
//
// MODULE: error
// PURPOSE: Single `VotingError` enum covering every fallible path in
//          the SDK. Variants are GROUPED by domain (lifecycle / voter
//          / state / ceremony / wire / external / catch-all), each
//          with a concise human-readable message.
//
// DESIGN:
//   * Typed variants over stringly-typed errors — callers can branch
//     on `NotDeployed`, `BelowThreshold`, etc. cleanly.
//   * `#[from]` impls for `hex::FromHexError`, `std::io::Error`, and
//     the `anyhow_compat::Error` catch-all so `?` propagation works
//     across different error sources.
//   * The `Other` catch-all wraps any `Error + Send + Sync` so we
//     can carry upstream errors without pulling `anyhow` into the
//     SDK's public surface.
//
// USAGE: every public SDK method returns `VotingResult<T> = Result<T,
//        VotingError>`. Callers match on variants for branch-on-error
//        UX (e.g., a UI shows "deploy first" for `NotDeployed` vs
//        "network down" for `Rpc(_)`).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VotingError {
    // ── Lifecycle ─────────────────────────────────────────────────────
    #[error("election has not been deployed yet")]
    NotDeployed,

    #[error("election has already been finalized")]
    AlreadyFinalized,

    #[error("election is not yet finalized")]
    NotFinalized,

    #[error("election is still in its registration / voting window")]
    StillOpen,

    #[error("election length window has not elapsed (need {required} more L1 blocks)")]
    HeightLockNotElapsed { required: u64 },

    // ── Voter / collateral ────────────────────────────────────────────
    #[error("voter pubkey is already registered")]
    AlreadyRegistered,

    #[error("voter pubkey is not registered")]
    NotRegistered,

    #[error("voter has already voted")]
    AlreadyVoted,

    #[error("voter has not voted yet")]
    NotVoted,

    #[error("voter has already initiated collateral release")]
    AlreadyReleased,

    #[error("two voter pubkeys hash to the same SPT slot ({slot})")]
    SlotCollision { slot: u64 },

    #[error("insufficient CAT collateral: need {required}, have {available}")]
    InsufficientCollateral { required: u64, available: u64 },

    #[error("insufficient XCH funds for registration fee + bundle fee")]
    InsufficientFunds,

    // ── State / proofs ────────────────────────────────────────────────
    #[error("local Merkle root does not match on-chain root (re-sync required)")]
    StateMismatch,

    #[error("Merkle proof verification failed")]
    InvalidMerkleProof,

    #[error("registered voter coin lineage does not trace back to the election singleton")]
    InvalidLineage,

    #[error("Groth16 proof generation failed: {0}")]
    ProvingError(String),

    #[error("Groth16 proof verification failed (off-chain pre-check)")]
    InvalidProof,

    #[error("BLS aggregate signature verification failed (off-chain pre-check)")]
    InvalidSignature,

    #[error("not enough signatures to satisfy 2k > registration_count")]
    BelowThreshold,

    // ── Ceremony ──────────────────────────────────────────────────────
    #[error("ceremony already finalized")]
    CeremonyFinalized,

    #[error("ceremony has zero contributions; refusing to use unsafe single-party setup")]
    UnsafeSingleParty,

    #[error("ceremony participant order / hash mismatch (corrupted transcript)")]
    CeremonyTranscriptCorrupt,

    // ── Wire / serialisation ──────────────────────────────────────────
    #[error("serialisation error: {0}")]
    Serialization(String),

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    // ── External ──────────────────────────────────────────────────────
    #[error("Chia RPC error: {0}")]
    Rpc(String),

    #[error("blockchain rejected spend bundle: {0}")]
    SpendRejected(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow_compat::Error),
}

pub type VotingResult<T> = Result<T, VotingError>;

// Tiny `anyhow`-shaped wrapper so the Other variant can absorb arbitrary
// errors without pulling anyhow into our public surface.
pub mod anyhow_compat {
    use std::fmt;

    #[derive(Debug)]
    pub struct Error(pub Box<dyn std::error::Error + Send + Sync + 'static>);

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.fmt(f)
        }
    }

    impl std::error::Error for Error {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.0.source()
        }
    }
}
