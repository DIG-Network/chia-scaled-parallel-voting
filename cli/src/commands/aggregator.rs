// ============================================================================
// commands/aggregator.rs — chain sync + finalize bundle production
// ============================================================================
//
// VERB: chip-voting aggregator
// PURPOSE: Run the off-chain proof producer. Two flows:
//          * `sync` / `collect-votes` — read-only diagnostics. Useful
//            for monitoring an in-flight election.
//          * `prepare-witness` / `finalize` — produce the spend
//            bundle that closes an election.
//
// PERFORMANCE: the prover is CPU-bound (~3s for 100 voters on a
// modern laptop, scaling roughly linearly with `MAX_SIGNERS`). For
// large elections, run on a dedicated machine; the CLI doesn't
// daemonise.

use anyhow::Result;
use chia_protocol::Bytes32;
use chip_voting_sdk::Aggregator;
use clap::Subcommand;
use std::path::PathBuf;

use crate::config_file;
use crate::output::Context;
use crate::rpc;
use crate::wallet as wallet_helpers;

#[derive(Debug, Subcommand)]
pub enum AggregatorCmd {
    /// Walk the chain to recover the current ElectionState and the
    /// registered voter set. Output mirrors `indexer status` plus the
    /// SPT root + a hash of the voter set for change detection.
    Sync {
        #[arg(long)]
        election_config: PathBuf,
    },

    /// Print the cached ElectionState (after sync). Mirrors
    /// `Aggregator::state`.
    State {
        #[arg(long)]
        election_config: PathBuf,
    },

    /// Print the cached voter set + SPT root (after sync). Mirrors
    /// `Aggregator::voter_set` + `Aggregator::merkle_tree`.
    VoterSet {
        #[arg(long)]
        election_config: PathBuf,
    },

    /// Print the candidate vote set — every voter who has cast a
    /// vote, with their (vote_data, signature) extracted from coin
    /// memos. Run after `sync` to inspect what `finalize` would feed
    /// into the prover.
    CollectVotes {
        #[arg(long)]
        election_config: PathBuf,
    },

    /// Pure off-chain witness preparation. No proof generated, no
    /// chain writes. Verifies the supplied votes constitute a valid
    /// majority + every BLS signature aggregates correctly. Useful
    /// for dry-running an election close before you commit prover
    /// time.
    PrepareWitness {
        #[arg(long)]
        election_config: PathBuf,

        /// Path to a votes JSON file: `[{"voter_pubkey_hex":"...",
        /// "vote_data_hex":"...", "vote_signature_hex":"..."}, ...]`.
        /// In production these are produced by `aggregator
        /// collect-votes`.
        #[arg(long)]
        votes_file: PathBuf,

        /// Vote outcome (32-byte hex). The bytes the election
        /// commits to on-chain.
        #[arg(long)]
        vote_outcome: String,
    },

    /// Build (and optionally broadcast) the finalize spend bundle
    /// — runs the Groth16 prover INTERNALLY using the supplied
    /// proving-key file. Mirrors `Aggregator::build_finalize`.
    BuildFinalize {
        #[arg(long)]
        election_config: PathBuf,

        #[arg(long)]
        votes_file: PathBuf,

        /// Vote outcome (32-byte hex).
        #[arg(long)]
        vote_outcome: String,

        /// Reward address (32-byte hex). Receives the accumulated
        /// registration fees.
        #[arg(long)]
        reward_address: String,

        /// Path to a binary file containing the arkworks-serialised
        /// `ArkProvingKey` (use
        /// `ark_serialize::CanonicalSerialize::serialize_compressed`
        /// with the prover's `ProvingKey<Bls12_381>`). The PK is
        /// large (~MB) and lives only in operator-controlled secure
        /// storage — never ship in `ElectionConfig`.
        #[arg(long)]
        proving_key_file: PathBuf,

        #[arg(long)]
        bundle_output: Option<PathBuf>,

        #[arg(long)]
        overwrite: bool,

        #[arg(long)]
        no_broadcast: bool,
    },

    /// Build (and optionally broadcast) the finalize spend bundle.
    /// Caller supplies a pre-computed Groth16 proof JSON file
    /// (typically produced by `chip-voting aggregator
    /// prepare-witness` + a separate proving service that holds the
    /// `ProvingKey` — that key is too large to ship in the
    /// `ElectionConfig` and lives only in operator-controlled
    /// secure storage).
    Finalize {
        #[arg(long)]
        election_config: PathBuf,

        #[arg(long)]
        votes_file: PathBuf,

        /// Vote outcome (32-byte hex).
        #[arg(long)]
        vote_outcome: String,

        /// Address (puzzle hash) that receives the accumulated
        /// registration fees as the prover's reward. 32-byte hex.
        #[arg(long)]
        reward_address: String,

        /// JSON file containing the pre-computed Groth16 proof
        /// `{"a_hex": "...", "b_hex": "...", "c_hex": "..."}`.
        /// Produced by your prover service from the witness
        /// emitted by `aggregator prepare-witness`.
        #[arg(long)]
        proof_file: PathBuf,

        /// If set, write the (signed) spend bundle here. Useful for
        /// archival even when broadcasting.
        #[arg(long)]
        bundle_output: Option<PathBuf>,

        /// Allow overwriting an existing bundle output file.
        #[arg(long)]
        overwrite: bool,

        /// Skip broadcasting — only emit the bundle file. Use for
        /// air-gapped relayer flows.
        #[arg(long)]
        no_broadcast: bool,
    },
}

pub async fn run(cmd: AggregatorCmd, ctx: &Context) -> Result<()> {
    match cmd {
        AggregatorCmd::Sync { election_config } => sync(election_config, ctx).await,
        AggregatorCmd::State { election_config } => state_cmd(election_config, ctx).await,
        AggregatorCmd::VoterSet { election_config } => voter_set_cmd(election_config, ctx).await,
        AggregatorCmd::CollectVotes { election_config } => {
            collect_votes(election_config, ctx).await
        }
        AggregatorCmd::PrepareWitness {
            election_config,
            votes_file,
            vote_outcome,
        } => prepare_witness(election_config, votes_file, vote_outcome, ctx).await,
        AggregatorCmd::Finalize {
            election_config,
            votes_file,
            vote_outcome,
            reward_address,
            proof_file,
            bundle_output,
            overwrite,
            no_broadcast,
        } => {
            finalize(
                election_config,
                votes_file,
                vote_outcome,
                reward_address,
                proof_file,
                bundle_output,
                overwrite,
                no_broadcast,
                ctx,
            )
            .await
        }
        AggregatorCmd::BuildFinalize {
            election_config,
            votes_file,
            vote_outcome,
            reward_address,
            proving_key_file,
            bundle_output,
            overwrite,
            no_broadcast,
        } => {
            build_finalize_cmd(
                election_config,
                votes_file,
                vote_outcome,
                reward_address,
                proving_key_file,
                bundle_output,
                overwrite,
                no_broadcast,
                ctx,
            )
            .await
        }
    }
}

async fn make_aggregator(config_path: PathBuf, ctx: &Context) -> Result<Aggregator> {
    let config = config_file::load_election_config(&config_path)?;
    let chain =
        wallet_helpers::make_independent_chain(ctx.network, ctx.rpc_override.as_deref()).await?;
    Ok(Aggregator::new(config, chain, ctx.network))
}

async fn sync(config_path: PathBuf, ctx: &Context) -> Result<()> {
    let mut agg = make_aggregator(config_path, ctx).await?;
    let snapshot = agg
        .sync()
        .await
        .map_err(|e| anyhow::anyhow!("aggregator sync: {e:?}"))?;
    let _ = agg.state().map_err(|e| anyhow::anyhow!("state: {e:?}"))?;
    ctx.print(&serde_json::json!({
        "election_launcher_id":     agg.config.election_launcher_id_hex,
        "registration_count":       snapshot.voter_set.registration_count,
        "registration_merkle_root": format!("0x{}", hex::encode(snapshot.voter_set.registration_merkle_root)),
        "accumulated_fees":         "(per-ballot — see ballot subcommand)",
        "finalized":                "(per-ballot — see ballot subcommand)",
        "vote_outcome":             "(per-ballot — see ballot subcommand)",
        "voter_count":              snapshot.voter_set.voters.len(),
    }))
}

async fn state_cmd(config_path: PathBuf, ctx: &Context) -> Result<()> {
    let mut agg = make_aggregator(config_path, ctx).await?;
    agg.sync()
        .await
        .map_err(|e| anyhow::anyhow!("aggregator sync: {e:?}"))?;
    let state = agg.state().map_err(|e| anyhow::anyhow!("state: {e:?}"))?;
    ctx.print(&serde_json::json!({
        "registration_count":       state.registration_count,
        "registration_merkle_root": format!("0x{}", hex::encode(state.registration_merkle_root)),
        "accumulated_fees":         "(per-ballot — see ballot subcommand)",
        "finalized":                "(per-ballot — see ballot subcommand)",
        "vote_outcome":             "(per-ballot — see ballot subcommand)",
    }))
}

async fn voter_set_cmd(config_path: PathBuf, ctx: &Context) -> Result<()> {
    let mut agg = make_aggregator(config_path, ctx).await?;
    agg.sync()
        .await
        .map_err(|e| anyhow::anyhow!("aggregator sync: {e:?}"))?;
    let set = agg
        .voter_set()
        .map_err(|e| anyhow::anyhow!("voter_set: {e:?}"))?;
    let smt = agg
        .merkle_tree()
        .map_err(|e| anyhow::anyhow!("merkle_tree: {e:?}"))?;
    let voters: Vec<_> = set
        .voters
        .iter()
        .map(|pk| {
            serde_json::json!({
                "pubkey_hex": format!("0x{}", hex::encode(pk.to_bytes())),
                "slot":       chip_voting_sdk::merkle::SparseMerkleTree::slot_for_pubkey(pk),
            })
        })
        .collect();
    ctx.print(&serde_json::json!({
        "registration_count":       set.registration_count,
        "registration_merkle_root": format!("0x{}", hex::encode(set.registration_merkle_root)),
        "smt_root":                 format!("0x{}", hex::encode(smt.root())),
        "voters":                   voters,
    }))
}

async fn collect_votes(config_path: PathBuf, ctx: &Context) -> Result<()> {
    let mut agg = make_aggregator(config_path, ctx).await?;
    agg.sync()
        .await
        .map_err(|e| anyhow::anyhow!("sync: {e:?}"))?;
    let votes = agg
        .collect_votes()
        .await
        .map_err(|e| anyhow::anyhow!("collect_votes: {e:?}"))?;
    let entries: Vec<_> = votes
        .iter()
        .map(|v| {
            serde_json::json!({
                "voter_pubkey_hex":   format!("0x{}", hex::encode(v.voter_pubkey.to_bytes())),
                "vote_data_hex":      format!("0x{}", hex::encode(v.vote_data)),
                "vote_signature_hex": format!("0x{}", v.vote_signature_hex),
            })
        })
        .collect();
    ctx.print(&serde_json::json!({
        "votes_collected": votes.len(),
        "votes":           entries,
    }))
}

async fn prepare_witness(
    config_path: PathBuf,
    votes_file: PathBuf,
    vote_outcome: String,
    ctx: &Context,
) -> Result<()> {
    let mut agg = make_aggregator(config_path, ctx).await?;
    agg.sync()
        .await
        .map_err(|e| anyhow::anyhow!("sync: {e:?}"))?;

    let votes = load_votes(&votes_file)?;
    let outcome = parse_b32(&vote_outcome, "vote_outcome")?;
    // TODO(phase-6): plumb the real ballot_launcher_id through CLI
    // args once per-ballot finalize is wired.
    let ballot_launcher_id = Bytes32::default();
    let witness = agg
        .prepare_finalize_witness(outcome, ballot_launcher_id, &votes)
        .map_err(|e| anyhow::anyhow!("prepare_finalize_witness: {e:?}"))?;

    ctx.print(&serde_json::json!({
        "vote_outcome":              format!("0x{}", hex::encode(witness.vote_outcome)),
        "vote_message":              format!("0x{}", hex::encode(witness.vote_message)),
        "agg_signers_pubkey":        format!("0x{}", hex::encode(witness.agg_signers.to_bytes())),
        "agg_signature":             format!("0x{}", hex::encode(witness.agg_signature.to_bytes())),
        "registration_count":        witness.registration_count,
        "registration_merkle_root":  format!("0x{}", hex::encode(witness.registration_merkle_root)),
        "signer_count":              witness.signer_pubkeys.len(),
        "merkle_proof_count":        witness.merkle_proofs.len(),
    }))
}

#[allow(clippy::too_many_arguments)]
async fn finalize(
    config_path: PathBuf,
    votes_file: PathBuf,
    vote_outcome: String,
    reward_address: String,
    proof_file: PathBuf,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    no_broadcast: bool,
    ctx: &Context,
) -> Result<()> {
    let mut agg = make_aggregator(config_path, ctx).await?;
    agg.sync()
        .await
        .map_err(|e| anyhow::anyhow!("sync: {e:?}"))?;
    let votes = load_votes(&votes_file)?;
    let outcome = parse_b32(&vote_outcome, "vote_outcome")?;
    let reward = parse_b32(&reward_address, "reward_address")?;
    let proof: chip_voting_sdk::Groth16Proof = config_file::load_json(&proof_file)?;

    let bundle = agg
        .build_finalize_with_proof(outcome, &votes, reward, proof)
        .await
        .map_err(|e| anyhow::anyhow!("build_finalize_with_proof: {e:?}"))?;

    let bundle_json = spend_bundle_to_json(&bundle);
    if let Some(path) = &bundle_output {
        config_file::save_json(path, &bundle_json, overwrite)?;
        tracing::info!(path = %path.display(), "wrote signed finalize bundle");
    }

    if no_broadcast {
        ctx.print(&serde_json::json!({
            "broadcast":    "skipped (--no-broadcast)",
            "bundle_file":  bundle_output.map(|p| p.display().to_string()),
            "coin_spends":  bundle.coin_spends.len(),
        }))?;
        return Ok(());
    }

    if !ctx.confirm("Broadcast the finalize bundle?")? {
        anyhow::bail!("user declined broadcast");
    }
    let chain =
        wallet_helpers::make_independent_chain(ctx.network, ctx.rpc_override.as_deref()).await?;
    let push = rpc::broadcast(&chain, &bundle).await?;
    ctx.print(&serde_json::json!({
        "broadcast":    push,
        "bundle_file":  bundle_output.map(|p| p.display().to_string()),
    }))
}

#[allow(clippy::too_many_arguments)]
async fn build_finalize_cmd(
    config_path: PathBuf,
    votes_file: PathBuf,
    vote_outcome: String,
    reward_address: String,
    proving_key_file: PathBuf,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    no_broadcast: bool,
    ctx: &Context,
) -> Result<()> {
    use ark_serialize::CanonicalDeserialize;

    let mut agg = make_aggregator(config_path, ctx).await?;
    agg.sync()
        .await
        .map_err(|e| anyhow::anyhow!("sync: {e:?}"))?;
    let votes = load_votes(&votes_file)?;
    let outcome = parse_b32(&vote_outcome, "vote_outcome")?;
    let reward = parse_b32(&reward_address, "reward_address")?;

    // Load the ProvingKey via arkworks compressed serialisation.
    let pk_bytes = std::fs::read(&proving_key_file)
        .map_err(|e| anyhow::anyhow!("reading proving key file: {e}"))?;
    let pk_inner = ark_groth16::ProvingKey::<ark_bls12_381::Bls12_381>::deserialize_compressed(
        pk_bytes.as_slice(),
    )
    .map_err(|e| anyhow::anyhow!("deserializing ProvingKey: {e}"))?;
    let pk = chip_voting_sdk::prover::circuit::ArkProvingKey(pk_inner);

    let bundle = agg
        .build_finalize(outcome, &votes, reward, &pk)
        .await
        .map_err(|e| anyhow::anyhow!("build_finalize: {e:?}"))?;

    let bundle_json = spend_bundle_to_json(&bundle);
    if let Some(path) = &bundle_output {
        config_file::save_json(path, &bundle_json, overwrite)?;
    }
    if no_broadcast {
        ctx.print(&serde_json::json!({
            "broadcast":   "skipped (--no-broadcast)",
            "bundle_file": bundle_output.map(|p| p.display().to_string()),
            "coin_spends": bundle.coin_spends.len(),
        }))?;
        return Ok(());
    }
    if !ctx.confirm("Broadcast the build-finalize bundle?")? {
        anyhow::bail!("user declined broadcast");
    }
    let chain =
        wallet_helpers::make_independent_chain(ctx.network, ctx.rpc_override.as_deref()).await?;
    let push = rpc::broadcast(&chain, &bundle).await?;
    ctx.print(&serde_json::json!({
        "broadcast":   push,
        "bundle_file": bundle_output.map(|p| p.display().to_string()),
    }))
}

fn load_votes(path: &std::path::Path) -> Result<Vec<chip_voting_sdk::VoteRecord>> {
    #[derive(serde::Deserialize)]
    struct Wire {
        voter_pubkey_hex: String,
        vote_data_hex: String,
        vote_signature_hex: String,
    }
    let wire: Vec<Wire> = config_file::load_json(path)?;
    wire.into_iter()
        .map(|w| {
            let pk_bytes = hex::decode(w.voter_pubkey_hex.trim().trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("voter_pubkey_hex: {e}"))?;
            let pk_arr: [u8; 48] = pk_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("voter_pubkey_hex: must be 48 bytes"))?;
            let pk = chia_bls::PublicKey::from_bytes(&pk_arr)
                .map_err(|e| anyhow::anyhow!("voter_pubkey: {e:?}"))?;
            let vd_bytes = hex::decode(w.vote_data_hex.trim().trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("vote_data_hex: {e}"))?;
            let vd_arr: [u8; 32] = vd_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("vote_data_hex: must be 32 bytes"))?;
            Ok(chip_voting_sdk::VoteRecord {
                voter_pubkey: pk,
                vote_data: Bytes32::new(vd_arr),
                vote_signature_hex: w
                    .vote_signature_hex
                    .trim()
                    .trim_start_matches("0x")
                    .to_string(),
                // For witness-prep flows, the registration coin id
                // isn't required by the prover — supply zeros.
                // `aggregator collect-votes` populates it correctly
                // from chain data.
                registration_coin_id: Bytes32::default(),
                // Per CHIP rev 2026-05-02: ballot/voting coin
                // identity is part of the record. For dry-run
                // witness flows these are placeholder zeros; the
                // real ids are populated by `aggregator
                // collect-votes` from chain data.
                ballot_launcher_id: Bytes32::default(),
                voting_coin_id: Bytes32::default(),
            })
        })
        .collect()
}

fn parse_b32(s: &str, name: &str) -> Result<Bytes32> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|_| anyhow::anyhow!("{name}: must be hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name}: must be exactly 32 bytes"))?;
    Ok(Bytes32::new(arr))
}

fn spend_bundle_to_json(b: &chia_protocol::SpendBundle) -> serde_json::Value {
    serde_json::json!({
        "coin_spends": b.coin_spends.iter().map(|cs| serde_json::json!({
            "coin": {
                "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                "puzzle_hash":      format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                "amount":           cs.coin.amount,
            },
            "puzzle_reveal_hex": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
            "solution_hex":      format!("0x{}", hex::encode(cs.solution.as_ref())),
        })).collect::<Vec<_>>(),
        "aggregated_signature": format!("0x{}", hex::encode(b.aggregated_signature.to_bytes())),
    })
}
