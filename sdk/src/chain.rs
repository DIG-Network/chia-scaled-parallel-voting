// ============================================================================
// chain.rs — chain-read abstraction for Aggregator + Indexer
// ============================================================================
//
// MODULE: chain
// PURPOSE: Decouple the chain-walking actors (Aggregator, Indexer) from
//          a specific chain client. Production callers use
//          `chia_query::ChiaQuery`; tests use `chia_sdk_test::Simulator`.
//
// DESIGN:
//   * Trait methods speak `chia_protocol` types (`Bytes32`, `Coin`,
//     `CoinSpend`) — the canonical Chia in-memory representation.
//   * `ChiaQuery` returns hex-encoded JSON strings; the impl below
//     adapts those into `chia_protocol` natively so callers never see
//     raw hex.
//   * `Simulator` already speaks `chia_protocol`; its impl is a thin
//     forwarder.
//   * Methods that don't apply to either backend (e.g., the simulator
//     can't push externally-built bundles for relay) are off-trait.
//
// CONTRACT (ALL IMPLS):
//   * `coin_records_by_puzzle_hash(ph, include_spent=false)` returns
//     ALL unspent coins at that puzzle hash. Singletons assume there
//     is at most one.
//   * `coin_records_by_hint(hint)` returns ALL coins (spent + unspent)
//     hinted by the given 32-byte hint.
//   * `puzzle_and_solution(coin_id)` returns `Some((puzzle, solution))`
//     iff the coin has been spent; `None` for unspent or unknown.
//
// THREAD-SAFETY: trait is `Send + Sync`. Impls of `&Simulator` borrow
//                immutably and so are safe to share across tasks (the
//                Simulator itself is intentionally not Sync because it
//                mutates on `spend_coins`; tests serialise these calls).

use async_trait::async_trait;
use chia_protocol::{Bytes32, Coin, Program};

use crate::error::{anyhow_compat, VotingError, VotingResult};

/// STRUCT: ChainCoinRecord
/// PURPOSE: minimum-shape coin record for ChainReader traits. Only the
///          fields Aggregator/Indexer actually need.
/// SOURCE: built by adapters from `chia_query::CoinRecord` (hex →
///         Bytes32) or directly from `chia_sdk_test::Simulator::CoinState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCoinRecord {
    pub coin: Coin,
    /// 0 = unspent, otherwise the L1 block height at which the coin
    /// was spent.
    pub spent_height: u32,
    /// L1 block height at which the coin first appeared. 0 = unknown
    /// (e.g., a synthetic test fixture).
    pub confirmed_height: u32,
}

impl ChainCoinRecord {
    pub fn is_unspent(&self) -> bool {
        self.spent_height == 0
    }
}

/// TRAIT: ChainReader
/// WHAT: minimum chain-read surface needed by Aggregator + Indexer.
/// IMPL: provided for `chia_query::ChiaQuery` (production) and
///       `&chia_sdk_test::Simulator` (tests; gated on a peer-simulator
///       feature... actually the Simulator type is unconditional in
///       chia-sdk-test 0.30 so no feature gate needed).
#[async_trait]
pub trait ChainReader: Send + Sync {
    /// FN: coin_records_by_puzzle_hash
    /// WHAT: return every unspent coin currently at `puzzle_hash`.
    /// USAGE: locate the latest unspent Election Singleton coin —
    ///        Aggregator calls this with the predicted singleton
    ///        puzzle hash and asserts the result has exactly one entry.
    async fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>>;

    /// FN: coin_records_by_hint
    /// WHAT: return every coin (spent + unspent) hinted by `hint`.
    /// USAGE: walk a voter's lineage. Voter hints are stable across
    ///        register / vote / release spends so this returns the
    ///        full history.
    async fn coin_records_by_hint(
        &self,
        hint: Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>>;

    /// FN: puzzle_and_solution
    /// WHAT: return the puzzle + solution that were used to spend
    ///       `coin_id`. `None` if the coin is unspent or unknown.
    /// USAGE: parse the action layer state out of a singleton's
    ///        previous spend, recover register-action arguments to
    ///        rebuild the voter set, etc.
    async fn puzzle_and_solution(
        &self,
        coin_id: Bytes32,
    ) -> VotingResult<Option<(Program, Program)>>;

    /// FN: coin_records_by_parent_ids
    /// WHAT: return every coin (spent + unspent) whose parent_coin_info
    ///       is in `parent_ids`. Used by lineage walks: given the
    ///       launcher's id, finds the eve singleton; given a spent
    ///       singleton's id, finds its child (the next singleton).
    /// FALLBACK: default impl returns Err so backends that don't
    ///           support parent-id lookups don't have to fail compile.
    ///           Both `chia_query::ChiaQuery` and `SharedSimulator`
    ///           override this with native implementations.
    async fn coin_records_by_parent_ids(
        &self,
        parent_ids: &[Bytes32],
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let _ = parent_ids;
        Err(VotingError::Other(anyhow_compat::Error(
            "coin_records_by_parent_ids: this backend doesn't implement parent-id lookups".into(),
        )))
    }

    /// FN: coin_record_by_id
    /// WHAT: direct point-lookup of a single coin by its 32-byte id.
    ///       Returns `Some(record)` whether the coin is spent OR
    ///       unspent (this is the ONLY way to find a launcher coin
    ///       on mainnet — `coin_records_by_puzzle_hash(SINGLETON_LAUNCHER_HASH)`
    ///       would return millions of unrelated launcher coins).
    /// USAGE: Voter / Aggregator lineage-proof reconstruction —
    ///        given a singleton's `parent_coin_info`, fetch the
    ///        launcher coin record directly.
    async fn coin_record_by_id(
        &self,
        coin_id: Bytes32,
    ) -> VotingResult<Option<ChainCoinRecord>>;

    /// FN: peak_height
    /// WHAT: current chain peak height the backend can see. Used
    ///       by propagation-aware polling: if the peak isn't
    ///       advancing while we wait, we know the peer pool is
    ///       stuck (and can surface that as a clearer error than
    ///       "coin not found").
    /// FALLBACK: default impl returns `None` for backends that
    ///           don't track height (e.g. a stub used in unit
    ///           tests). Production backends override.
    async fn peak_height(&self) -> VotingResult<Option<u32>> {
        Ok(None)
    }
}

/// FN: wait_for_unspent_coin_at_puzzle_hash
/// WHAT: poll `chain.coin_records_by_puzzle_hash(ph)` until at
///       least one UNSPENT record exists, OR `max_wait` elapses.
///       Logs peak-height progression so propagation lag vs. a
///       stuck peer pool are easy to distinguish.
///
/// USAGE: locating a coin at a **fixed** puzzle hash after a
///        spend (e.g. a standard p2 change output). For the
///        **Election Singleton**, puzzle hash changes whenever
///        inner state changes — use
///        [`crate::actors::aggregator::wait_for_current_singleton`]
///        (launcher-id lineage walk) instead.
///
/// ALSO: any actor that just broadcast a spend bundle and
///        immediately needs to find one of its outputs. On
///        mainnet, peer propagation can take up to 2 blocks
///        (~100s) AFTER `wait_for_confirmation` returns —
///        chia_query's internal peer pool may be hitting peers
///        that lag the one which confirmed the spend.
///
/// CONTRACT:
///   * `poll_interval` — sleep between attempts. 30s is the
///     recommended floor on mainnet (tighter just hammers the
///     RPC without helping; mainnet blocks are ~52s).
///   * `max_wait` — total budget. 5 min on mainnet covers two
///     full block intervals plus farmer-queue jitter.
///   * `expected_min` — how many unspent records satisfy the
///     wait. Singleton lookups want 1; multi-coin queries can
///     want more.
///
/// ERRORS: `VotingError::Other(_)` with the elapsed time and
/// last-seen peak height embedded in the message — useful for
/// distinguishing "peers stuck" from "coin actually missing".
pub async fn wait_for_unspent_coin_at_puzzle_hash<C: ChainReader>(
    chain: &C,
    puzzle_hash: Bytes32,
    label: &str,
    poll_interval: std::time::Duration,
    max_wait: std::time::Duration,
    expected_min: usize,
) -> VotingResult<Vec<ChainCoinRecord>> {
    let started = std::time::Instant::now();
    let mut last_peak: Option<u32> = None;
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        // Track peak height so a stuck peer pool surfaces clearly.
        if let Ok(Some(h)) = chain.peak_height().await {
            if last_peak.map(|p| h != p).unwrap_or(true) {
                tracing::debug!(
                    label,
                    attempt,
                    peak_height = h,
                    "wait_for_unspent_coin: peer pool peak height update"
                );
                last_peak = Some(h);
            }
        }

        let records = chain.coin_records_by_puzzle_hash(puzzle_hash).await?;
        let unspent: Vec<_> = records
            .into_iter()
            .filter(|r| r.is_unspent())
            .collect();
        if unspent.len() >= expected_min {
            tracing::info!(
                label,
                attempt,
                elapsed_secs = started.elapsed().as_secs(),
                count = unspent.len(),
                "{} visible — proceeding",
                label
            );
            return Ok(unspent);
        }

        let elapsed = started.elapsed();
        if elapsed >= max_wait {
            return Err(VotingError::Other(anyhow_compat::Error(
                format!(
                    "{label}: no unspent coin at puzzle_hash {} after {}s ({} attempts, last_peak={:?}). \
                     Peer pool may be stuck or the coin was never broadcast.",
                    hex::encode(puzzle_hash),
                    elapsed.as_secs(),
                    attempt,
                    last_peak,
                )
                .into(),
            )));
        }

        tracing::info!(
            label,
            attempt,
            elapsed_secs = elapsed.as_secs(),
            poll_interval_secs = poll_interval.as_secs(),
            peak_height = ?last_peak,
            "{} not visible yet — sleeping before retry",
            label
        );
        tokio::time::sleep(poll_interval).await;
    }
}

// ── chia_query::ChiaQuery adapter ─────────────────────────────────────

#[async_trait]
impl ChainReader for chia_query::ChiaQuery {
    async fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        // chia_query takes a 0x-prefixed hex string (it strips the
        // prefix internally if present, but the convention is to send
        // it). include_spent_coins=false → only unspent; height bounds
        // None,None → full history.
        let ph_hex = format!("0x{}", hex::encode(puzzle_hash));
        let records = self
            .get_coin_records_by_puzzle_hash(&ph_hex, None, None, false)
            .await
            .map_err(|e| rpc_err("get_coin_records_by_puzzle_hash", e))?;
        records
            .iter()
            .map(adapt_record)
            .collect::<Result<Vec<_>, _>>()
    }

    async fn coin_records_by_hint(
        &self,
        hint: Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let hint_hex = format!("0x{}", hex::encode(hint));
        // include_spent_coins=true to get the FULL voter lineage.
        let records = self
            .get_coin_records_by_hint(&hint_hex, None, None, true)
            .await
            .map_err(|e| rpc_err("get_coin_records_by_hint", e))?;
        records
            .iter()
            .map(adapt_record)
            .collect::<Result<Vec<_>, _>>()
    }

    async fn puzzle_and_solution(
        &self,
        coin_id: Bytes32,
    ) -> VotingResult<Option<(Program, Program)>> {
        let id_hex = format!("0x{}", hex::encode(coin_id));
        // chia_query's get_puzzle_and_solution returns
        // CoinSpend{puzzle_reveal, solution} both as hex strings, OR
        // an Err if the coin is unspent. We treat NotFound-style RPC
        // errors as `None`, propagate other errors.
        // chia_query 0.2 added a `height: Option<u32>` parameter; pass
        // `None` to let the backend pick the spend at the most recent
        // height (the only place the coin appears).
        match self.get_puzzle_and_solution(&id_hex, None).await {
            Ok(spend) => {
                let puzzle = parse_program(&spend.puzzle_reveal)?;
                let solution = parse_program(&spend.solution)?;
                Ok(Some((puzzle, solution)))
            }
            Err(_) => Ok(None),
        }
    }

    async fn coin_records_by_parent_ids(
        &self,
        parent_ids: &[Bytes32],
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let hex_ids: Vec<String> = parent_ids
            .iter()
            .map(|id| format!("0x{}", hex::encode(id)))
            .collect();
        let records = self
            .get_coin_records_by_parent_ids(&hex_ids, None, None, true)
            .await
            .map_err(|e| rpc_err("get_coin_records_by_parent_ids", e))?;
        records.iter().map(adapt_record).collect()
    }

    async fn coin_record_by_id(
        &self,
        coin_id: Bytes32,
    ) -> VotingResult<Option<ChainCoinRecord>> {
        let id_hex = format!("0x{}", hex::encode(coin_id));
        // chia_query returns Err for "not found"; we treat that as
        // `Ok(None)` so callers can branch on absence vs RPC error.
        match self.get_coin_record_by_name(&id_hex).await {
            Ok(rec) => adapt_record(&rec).map(Some),
            Err(_) => Ok(None),
        }
    }

    async fn peak_height(&self) -> VotingResult<Option<u32>> {
        // chia_query auto-rotates peers + falls back to coinset.org
        // for `get_blockchain_state` so this just transparently
        // returns the freshest peak any backend is willing to give.
        match self.get_blockchain_state().await {
            Ok(state) => Ok(state.peak.map(|p| p.height)),
            Err(e) => {
                tracing::debug!(error = ?e, "peak_height: get_blockchain_state failed");
                Ok(None)
            }
        }
    }
}

// ── chia_query::coinset::CoinsetClient adapter ────────────────────────
//
// The router-backed `ChiaQuery` does peer → peer-retry → coinset for
// every read AND for `push_tx`. In our experience on mainnet that
// "first peer wins the ack" semantic is the source of two distinct
// flakes:
//
//   1. `coin_records_by_*` returns whatever the FIRST peer indexed,
//      which may lag the latest block by 1–2 slots — so a freshly
//      spent coin can come back as "still unspent" until the
//      caller's pool happens to rotate to a different peer.
//
//   2. `push_tx` returns the FIRST peer's `TransactionAck` verbatim —
//      including `status=FAILED` from a peer with a stale singleton
//      tip view, even when other peers and `api.coinset.org`'s full
//      node would have admitted the bundle.
//
// For both reasons production CHIP code prefers a single canonically-
// synced backend (`https://api.coinset.org`) over a peer pool with
// varying tip ages. This impl lets callers construct a
// `chia_query::coinset::CoinsetClient` directly and pass it to
// `Aggregator`, `Voter`, `Oracle`, etc. as a `ChainReader` — no
// peer pool, no router fan-out, no certificate / TLS setup.

#[async_trait]
impl ChainReader for chia_query::coinset::CoinsetClient {
    async fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let ph_hex = format!("0x{}", hex::encode(puzzle_hash));
        let records = self
            .get_coin_records_by_puzzle_hash(&ph_hex, None, None, false)
            .await
            .map_err(|e| rpc_err("get_coin_records_by_puzzle_hash", e))?;
        records.iter().map(adapt_record).collect()
    }

    async fn coin_records_by_hint(
        &self,
        hint: Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let hint_hex = format!("0x{}", hex::encode(hint));
        let records = self
            .get_coin_records_by_hint(&hint_hex, None, None, true)
            .await
            .map_err(|e| rpc_err("get_coin_records_by_hint", e))?;
        records.iter().map(adapt_record).collect()
    }

    async fn puzzle_and_solution(
        &self,
        coin_id: Bytes32,
    ) -> VotingResult<Option<(Program, Program)>> {
        let id_hex = format!("0x{}", hex::encode(coin_id));
        match self.get_puzzle_and_solution(&id_hex, None).await {
            Ok(spend) => {
                let puzzle = parse_program(&spend.puzzle_reveal)?;
                let solution = parse_program(&spend.solution)?;
                Ok(Some((puzzle, solution)))
            }
            Err(_) => Ok(None),
        }
    }

    async fn coin_records_by_parent_ids(
        &self,
        parent_ids: &[Bytes32],
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let hex_ids: Vec<String> = parent_ids
            .iter()
            .map(|id| format!("0x{}", hex::encode(id)))
            .collect();
        let records = self
            .get_coin_records_by_parent_ids(&hex_ids, None, None, true)
            .await
            .map_err(|e| rpc_err("get_coin_records_by_parent_ids", e))?;
        records.iter().map(adapt_record).collect()
    }

    async fn coin_record_by_id(
        &self,
        coin_id: Bytes32,
    ) -> VotingResult<Option<ChainCoinRecord>> {
        let id_hex = format!("0x{}", hex::encode(coin_id));
        match self.get_coin_record_by_name(&id_hex).await {
            Ok(rec) => adapt_record(&rec).map(Some),
            Err(_) => Ok(None),
        }
    }

    async fn peak_height(&self) -> VotingResult<Option<u32>> {
        match self.get_blockchain_state().await {
            Ok(state) => Ok(state.peak.map(|p| p.height)),
            Err(e) => {
                tracing::debug!(error = ?e, "peak_height (coinset): get_blockchain_state failed");
                Ok(None)
            }
        }
    }
}

// ── chia_sdk_test::Simulator adapter (used by integration tests) ──────
//
// `chia_sdk_test` is a dev-dependency so this whole submodule only
// compiles in test builds. Downstream crates that want this adapter
// in their own integration tests can copy the SharedSimulator pattern
// or add chia-sdk-test as their own dev-dep.

#[cfg(test)]
mod simulator_impl {
    use super::*;
    use chia_sdk_test::Simulator;

    /// STRUCT: SharedSimulator
    /// PURPOSE: ChainReader-implementing wrapper around a shared
    ///          mutable reference to a `chia_sdk_test::Simulator`. The
    ///          tests construct one Simulator and pass it to multiple
    ///          actors; this wrapper Mutex-protects the shared access.
    /// SAFETY:  the raw pointer is only dereferenced under the Mutex;
    ///          tests serialise calls so there is never concurrent
    ///          aliased &mut access in practice.
    pub struct SharedSimulator(pub std::sync::Arc<std::sync::Mutex<*mut Simulator>>);

    // SAFETY: the *mut Simulator is only accessed through the Mutex's
    // exclusive lock; tests serialise access. Send+Sync are required
    // so Aggregator<C: ChainReader>'s C bound is satisfied.
    unsafe impl Send for SharedSimulator {}
    unsafe impl Sync for SharedSimulator {}

    impl SharedSimulator {
        /// Build from a raw `&mut Simulator`. The borrow MUST outlive
        /// every actor that holds the resulting `SharedSimulator`.
        ///
        /// SAFETY: caller guarantees no concurrent &mut access during
        /// the lifetime of the returned `SharedSimulator`.
        #[allow(clippy::arc_with_non_send_sync)] // SAFETY contract on the *mut is documented above.
        pub fn new(sim: &mut Simulator) -> Self {
            Self(std::sync::Arc::new(std::sync::Mutex::new(sim as *mut _)))
        }
    }

    #[async_trait]
    impl ChainReader for SharedSimulator {
        async fn coin_records_by_puzzle_hash(
            &self,
            puzzle_hash: Bytes32,
        ) -> VotingResult<Vec<ChainCoinRecord>> {
            use indexmap::indexset;
            let guard = self.0.lock().expect("simulator mutex poisoned");
            // SAFETY: see SharedSimulator::new contract.
            let sim: &Simulator = unsafe { &**guard };
            // Simulator API: `lookup_puzzle_hashes(set, include_hints)`
            // returns ALL coin states (spent + unspent) at any of the
            // given puzzle hashes. We filter to unspent here to match
            // the chia-query adapter's behaviour.
            Ok(sim
                .lookup_puzzle_hashes(indexset![puzzle_hash], false)
                .into_iter()
                .filter(|cs| cs.spent_height.is_none())
                .map(|cs| ChainCoinRecord {
                    coin: cs.coin,
                    spent_height: 0,
                    confirmed_height: cs.created_height.unwrap_or(0),
                })
                .collect())
        }

        async fn coin_records_by_hint(
            &self,
            hint: Bytes32,
        ) -> VotingResult<Vec<ChainCoinRecord>> {
            let guard = self.0.lock().expect("simulator mutex poisoned");
            let sim: &Simulator = unsafe { &**guard };
            let coin_ids = sim.hinted_coins(hint);
            Ok(coin_ids
                .into_iter()
                .filter_map(|id| sim.coin_state(id))
                .map(|cs| ChainCoinRecord {
                    coin: cs.coin,
                    spent_height: cs.spent_height.unwrap_or(0),
                    confirmed_height: cs.created_height.unwrap_or(0),
                })
                .collect())
        }

        async fn puzzle_and_solution(
            &self,
            coin_id: Bytes32,
        ) -> VotingResult<Option<(Program, Program)>> {
            let guard = self.0.lock().expect("simulator mutex poisoned");
            let sim: &Simulator = unsafe { &**guard };
            Ok(sim.puzzle_and_solution(coin_id))
        }

        async fn coin_record_by_id(
            &self,
            coin_id: Bytes32,
        ) -> VotingResult<Option<ChainCoinRecord>> {
            let guard = self.0.lock().expect("simulator mutex poisoned");
            // SAFETY: see SharedSimulator::new contract.
            let sim: &Simulator = unsafe { &**guard };
            Ok(sim.coin_state(coin_id).map(|cs| ChainCoinRecord {
                coin: cs.coin,
                spent_height: cs.spent_height.unwrap_or(0),
                confirmed_height: cs.created_height.unwrap_or(0),
            }))
        }

        async fn coin_records_by_parent_ids(
            &self,
            parent_ids: &[Bytes32],
        ) -> VotingResult<Vec<ChainCoinRecord>> {
            let guard = self.0.lock().expect("simulator mutex poisoned");
            let sim: &Simulator = unsafe { &**guard };
            let mut out = Vec::new();
            for &parent_id in parent_ids {
                for cs in sim.children(parent_id) {
                    out.push(ChainCoinRecord {
                        coin: cs.coin,
                        spent_height: cs.spent_height.unwrap_or(0),
                        confirmed_height: cs.created_height.unwrap_or(0),
                    });
                }
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
pub use simulator_impl::*;

// ── Adapters / parsing helpers ───────────────────────────────────────

fn rpc_err(op: &str, e: chia_query::ChiaQueryError) -> VotingError {
    VotingError::Rpc(format!("{op}: {e}"))
}

fn adapt_record(r: &chia_query::CoinRecord) -> VotingResult<ChainCoinRecord> {
    let coin = adapt_coin(&r.coin)?;
    Ok(ChainCoinRecord {
        coin,
        spent_height: r.spent_block_index,
        confirmed_height: r.confirmed_block_index,
    })
}

fn adapt_coin(c: &chia_query::Coin) -> VotingResult<Coin> {
    let parent = parse_hex32(&c.parent_coin_info)?;
    let ph = parse_hex32(&c.puzzle_hash)?;
    Ok(Coin::new(parent, ph, c.amount))
}

fn parse_hex32(s: &str) -> VotingResult<Bytes32> {
    let trimmed = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|e| VotingError::Other(anyhow_compat::Error(format!(
            "hex decode {s}: {e}").into())))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        VotingError::Other(anyhow_compat::Error(format!("expected 32 bytes from {s}").into()))
    })?;
    Ok(Bytes32::new(arr))
}

fn parse_program(hex_str: &str) -> VotingResult<Program> {
    let trimmed = hex_str.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|e| VotingError::Other(anyhow_compat::Error(format!(
            "hex decode {hex_str}: {e}").into())))?;
    Ok(Program::from(bytes))
}

// ============================================================================
// Tests
// ============================================================================
//
// CHAIN-READER UNIT TESTS
//
// These tests exercise the trait shape against the simulator-backed
// adapter (the most readily-testable backend). The ChiaQuery adapter
// is exercised indirectly via real-network smoke tests and by the
// type system (it must implement the trait or the crate doesn't
// compile).

#[cfg(test)]
mod tests {
    use super::*;
    use chia_sdk_test::Simulator;

    /// WHAT: an unspent coin at a known puzzle hash is found by
    ///       `coin_records_by_puzzle_hash`.
    /// HOW:  pre-fund a standard p2 coin via `sim.bls(amount)`,
    ///       wrap the simulator in a SharedSimulator, query for the
    ///       coin's puzzle hash, assert exactly one record returned
    ///       and that the coin matches.
    /// WHY:  baseline read path Aggregator::sync uses to find the
    ///       Election Singleton. Pinning it ensures the adapter and
    ///       trait shape stay aligned with the simulator's behaviour.
    #[tokio::test(flavor = "current_thread")]
    async fn shared_simulator_finds_unspent_coin_by_puzzle_hash() {
        let mut sim = Simulator::new();
        let alice = sim.bls(1_000);

        let chain = SharedSimulator::new(&mut sim);
        let records = chain
            .coin_records_by_puzzle_hash(alice.puzzle_hash)
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].coin, alice.coin);
        assert!(records[0].is_unspent());
    }

    /// WHAT: `puzzle_and_solution` returns `None` for an unspent coin.
    /// HOW:  pre-fund a coin (which is therefore unspent), query
    ///       `puzzle_and_solution`, assert `None`.
    /// WHY:  Aggregator::sync uses this method to recover the
    ///       singleton's prior state; the `None` branch must be a
    ///       distinguishable, non-error value so callers can branch
    ///       on "this coin hasn't been spent yet" cleanly.
    #[tokio::test(flavor = "current_thread")]
    async fn shared_simulator_unspent_coin_has_no_puzzle_and_solution() {
        let mut sim = Simulator::new();
        let alice = sim.bls(1);
        let coin_id = alice.coin.coin_id();

        let chain = SharedSimulator::new(&mut sim);
        assert!(chain.puzzle_and_solution(coin_id).await.unwrap().is_none());
    }
}
