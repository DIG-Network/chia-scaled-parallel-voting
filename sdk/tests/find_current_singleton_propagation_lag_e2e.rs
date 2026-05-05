//! Regression: `find_current_singleton` MUST NOT return a tip whose
//! "unspent" status comes only from the secondary `coin_records_by_*`
//! indices when the primary `coin_record_by_id` view says it's already
//! spent.
//!
//! Failure mode this guards against (mainnet 2026-05-05 run #4):
//!   * voter2's register confirmed at T0 (primary index updated).
//!   * 334 ms later, `BallotIssuer::create_ballot` called the launcher
//!     walker. coinset.org's `coin_records_by_puzzle_hash` (secondary
//!     index) hadn't propagated voter2's spend yet and still returned
//!     the post-voter1 / pre-voter2 singleton as unspent.
//!   * The walker trusted the secondary view and returned the stale
//!     tip. `create_ballot` built a bundle wrapping that stale coin.
//!   * Mempool rejected with `MINTING_COIN` (the recreated singleton
//!     from voter2's register already occupies the next-singleton coin
//!     id slot the create_ballot bundle attempted to fill).
//!
//! The fix double-checks every "unspent" candidate via the primary
//! `coin_record_by_id` index and falls through to the slow lineage
//! walker if primary disagrees. This test asserts that fall-through
//! happens.

use std::sync::Mutex;

use async_trait::async_trait;
use chia_protocol::{Bytes32, Coin, Program};
use chip_voting_sdk::actors::aggregator::{
    compute_eve_singleton_puzzle_hash, find_current_singleton,
};
use chip_voting_sdk::chain::{ChainCoinRecord, ChainReader};
use chip_voting_sdk::config::{ElectionConfig, MAX_SIGNERS, PUBLIC_INPUT_COUNT, TREE_DEPTH};

#[allow(dead_code)]
const _USE: usize = PUBLIC_INPUT_COUNT;
use chip_voting_sdk::error::{VotingError, VotingResult};

/// ChainReader mock that simulates the exact propagation-lag race
/// observed on mainnet: secondary index says one coin is unspent, but
/// primary index says it's spent.
struct StaleSecondaryIndexMock {
    eve_coin: Coin,
    /// Records calls by name so the test can verify the walker
    /// consulted the primary index after the secondary returned the
    /// stale "unspent" candidate.
    calls: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl ChainReader for StaleSecondaryIndexMock {
    async fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        self.calls.lock().unwrap().push("by_puzzle_hash");
        if puzzle_hash == self.eve_coin.puzzle_hash {
            // Lie: secondary index claims eve is unspent.
            Ok(vec![ChainCoinRecord {
                coin: self.eve_coin,
                spent_height: 0, // STALE
                confirmed_height: 100,
            }])
        } else {
            Ok(vec![])
        }
    }

    async fn coin_record_by_id(&self, coin_id: Bytes32) -> VotingResult<Option<ChainCoinRecord>> {
        self.calls.lock().unwrap().push("by_id");
        if coin_id == self.eve_coin.coin_id() {
            // Truth: primary index says eve was spent at block 105.
            // The fix must observe this and reject the stale candidate.
            Ok(Some(ChainCoinRecord {
                coin: self.eve_coin,
                spent_height: 105, // PRIMARY: actually spent
                confirmed_height: 100,
            }))
        } else {
            Ok(None)
        }
    }

    async fn coin_records_by_parent_ids(
        &self,
        _parent_ids: &[Bytes32],
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        self.calls.lock().unwrap().push("by_parent_ids");
        // Slow path: empty children. The walker should give up with
        // NotDeployed once the fast path correctly rejects the stale
        // eve and falls through.
        Ok(vec![])
    }

    async fn coin_records_by_hint(&self, _hint: Bytes32) -> VotingResult<Vec<ChainCoinRecord>> {
        Ok(vec![])
    }

    async fn puzzle_and_solution(
        &self,
        _coin_id: Bytes32,
    ) -> VotingResult<Option<(Program, Program)>> {
        Ok(None)
    }
}

fn good_config(launcher_id: Bytes32) -> ElectionConfig {
    ElectionConfig {
        tree_depth: TREE_DEPTH,
        max_signers: MAX_SIGNERS,
        cat_tail_hash_hex: hex::encode([0x77u8; 32]),
        verification_key_hex: hex::encode(vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48]),
        collateral_amount: 100,
        election_launcher_id_hex: hex::encode(launcher_id),
        label: None,
    }
}

#[tokio::test]
async fn find_current_singleton_rejects_stale_secondary_index_unspent() {
    let launcher_id = Bytes32::new([0xAB; 32]);
    let config = good_config(launcher_id);
    // Compute the eve puzzle hash the walker will look for.
    let eve_ph = compute_eve_singleton_puzzle_hash(&config, 0);
    let eve_coin = Coin::new(launcher_id, eve_ph, 1);
    let chain = StaleSecondaryIndexMock {
        eve_coin,
        calls: Mutex::new(Vec::new()),
    };

    let result = find_current_singleton(&chain, &config, 0).await;

    // With the fix, the walker observes that primary says eve is
    // spent — even though secondary index lied — and falls through to
    // the slow path. The slow path's `coin_records_by_parent_ids`
    // returns no children, so the walker bails NotDeployed.
    //
    // Without the fix: the walker would have returned eve as "the
    // current singleton" — a stale tip that the next mainnet spend
    // would fail to consume (MINTING_COIN / DOUBLE_SPEND).
    let calls = chain.calls.lock().unwrap().clone();
    assert!(
        calls.contains(&"by_id"),
        "fix MUST consult primary index `coin_record_by_id` to verify the secondary's \
         claim — observed call sequence: {calls:?}"
    );
    match result {
        Err(VotingError::NotDeployed) => {
            // expected: the fast-path correctly rejected the stale
            // candidate and the slow path had nothing to walk.
        }
        Ok(cs) => panic!(
            "fix regression: walker returned stale eve as current tip \
             (coin_id={}). The primary index says it's spent at height \
             105. Observed calls: {:?}",
            hex::encode(cs.coin.coin_id()),
            chain.calls.lock().unwrap()
        ),
        Err(e) => panic!(
            "unexpected error: {e:?} (calls: {:?})",
            chain.calls.lock().unwrap()
        ),
    }
}
