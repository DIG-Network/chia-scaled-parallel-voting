// ============================================================================
// examples/run_ceremony.rs — regenerate the 6-input VK fixture
// ============================================================================
//
// PURPOSE: Drive a complete simulated MPC ceremony (Coordinator + 2
//          participants + SimulatedBackend) for the new 6-public-input
//          VotingCircuit shape and write the resulting `VerificationKey`
//          to `app/data/vk-2026-05-02.bin` in the canonical
//          chunked layout
//          `alpha_g1 || beta_g2 || gamma_g2 || delta_g2 || ic0..ic6`
//          (672 bytes — matches `ElectionConfig::verification_key_hex`
//          and `vk_chia_chunked_bytes_is_672_bytes`).
//
// WHY:    Phase 1 of the CHIP migration (rev 2026-05-02) added a 6th
//          public input (`ballot_launcher_id`) to the voting circuit,
//          changing the VK byte length from 576 → 672. Any test
//          fixture that embedded the OLD 4-public-input VK is now
//          stale; this example produces the canonical replacement
//          and is the reproducible source of truth.
//
// NOT FOR PRODUCTION: SimulatedBackend derives the trusted setup
//          deterministically from the public transcript — anyone who
//          reads the transcript can forge proofs. Acceptable ONLY for
//          regenerating a *test fixture* whose purpose is to assert
//          on-the-wire layout / length, not unforgeability. Real
//          deployments must run a real MPC backend (`phase2`,
//          `arkworks-snark-mpc`).
//
// USAGE:  `cargo run --example run_ceremony --release` from the
//          workspace root or the `sdk/` directory.

use std::path::PathBuf;

use chip_voting_sdk::ceremony::{
    CeremonyCoordinator, CeremonyParticipant, SimulatedBackend,
};
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Initialise coordinator + start a fresh ceremony ────────
    let mut coord = CeremonyCoordinator::new(Box::new(SimulatedBackend));
    coord.start("chip-voting-v1".into())?;

    // ── 2. Two independent participants contribute. The MPC
    //       soundness guarantee only requires ONE honest contribution,
    //       but two exercises the chain-link validation in the
    //       coordinator (single-party setups are explicitly rejected
    //       by `finalize` with `UnsafeSingleParty`).
    let alice = CeremonyParticipant::new(
        Box::new(SimulatedBackend),
        "alice".into(),
        Some("CHIP rev 2026-05-02 — phase 5.3 fixture regeneration".into()),
    );
    let bob = CeremonyParticipant::new(
        Box::new(SimulatedBackend),
        "bob".into(),
        Some("CHIP rev 2026-05-02 — phase 5.3 fixture regeneration".into()),
    );

    let t1 = coord.current_transcript()?.clone();
    let alice_out = alice.contribute(&t1, [0xAAu8; 32])?;
    coord.accept_contribution(alice_out.transcript)?;

    let t2 = coord.current_transcript()?.clone();
    let bob_out = bob.contribute(&t2, [0xBBu8; 32])?;
    coord.accept_contribution(bob_out.transcript)?;

    // ── 3. Finalise → 672-byte chunked VK ─────────────────────────
    let vk = coord.finalize()?;
    let expected_len = 336 + (PUBLIC_INPUT_COUNT + 1) * 48;
    assert_eq!(
        vk.raw_bytes.len(),
        expected_len,
        "VK length mismatch: expected {expected_len}, got {} — \
         circuit shape may have drifted from PUBLIC_INPUT_COUNT = {PUBLIC_INPUT_COUNT}",
        vk.raw_bytes.len(),
    );

    // ── 4. Locate `<repo>/app/data/vk-2026-05-02.bin`. CARGO_MANIFEST_DIR
    //       points at `sdk/`; the repo root is its parent.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .ok_or("CARGO_MANIFEST_DIR has no parent — unexpected layout")?;
    let out_dir = repo_root.join("app").join("data");
    std::fs::create_dir_all(&out_dir)?;
    let out_path = out_dir.join("vk-2026-05-02.bin");
    std::fs::write(&out_path, &vk.raw_bytes)?;

    println!(
        "wrote {} ({} bytes — expected {})",
        out_path.display(),
        vk.raw_bytes.len(),
        expected_len,
    );
    println!(
        "contributions: {} (attestations: {})",
        coord.contribution_count(),
        coord.published_attestations()?.len(),
    );

    Ok(())
}
