//! One-shot mainnet diagnostic: query the already-deployed eve singleton
//! using the same chia_query::CoinsetClient the live test wires into the
//! Aggregator. Prints what each query path returns so we can localise why
//! Aggregator::sync's `coin_records_by_puzzle_hash` returned 0 records
//! while a direct coinset.org HTTP call returned 1.

use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let chain = chia_query::coinset::CoinsetClient::new(
        "https://api.coinset.org",
        Duration::from_secs(30),
    )?;

    let launcher_hex =
        "0x599be77e7725f15b2bc2439a675a3dada0d17a14342ae7af49209af7588555bc";
    let eve_id_hex =
        "0x05be5e6eb0de82e620c578fce4bcd34d75d218de38fac5ce7d0fbc1916a834ba";
    let eve_ph_hex =
        "0x5d8289d73685b36eab726c38775b615340bfe0e1969a7c9a8e1867390002a42f";

    eprintln!("== get_coin_record_by_name(eve_id) ==");
    match chain.get_coin_record_by_name(eve_id_hex).await {
        Ok(r) => eprintln!(
            "  ok: spent={:?} confirmed={} ph={:?}",
            r.spent, r.confirmed_block_index, r.coin.puzzle_hash
        ),
        Err(e) => eprintln!("  err: {e}"),
    }

    eprintln!("== get_coin_records_by_puzzle_hash(eve_ph, include_spent=false) ==");
    match chain
        .get_coin_records_by_puzzle_hash(eve_ph_hex, None, None, false)
        .await
    {
        Ok(rs) => {
            eprintln!("  ok: {} records", rs.len());
            for (i, r) in rs.iter().enumerate() {
                eprintln!(
                    "  [{i}] amount={} spent={:?} confirmed={} ph={:?}",
                    r.coin.amount, r.spent, r.confirmed_block_index, r.coin.puzzle_hash
                );
            }
        }
        Err(e) => eprintln!("  err: {e}"),
    }

    eprintln!("== get_coin_records_by_parent_ids([launcher], include_spent=true) ==");
    match chain
        .get_coin_records_by_parent_ids(&[launcher_hex.to_string()], None, None, true)
        .await
    {
        Ok(rs) => {
            eprintln!("  ok: {} records", rs.len());
            for (i, r) in rs.iter().enumerate() {
                eprintln!(
                    "  [{i}] amount={} spent={:?} ph={:?}",
                    r.coin.amount, r.spent, r.coin.puzzle_hash
                );
            }
        }
        Err(e) => eprintln!("  err: {e}"),
    }

    Ok(())
}
