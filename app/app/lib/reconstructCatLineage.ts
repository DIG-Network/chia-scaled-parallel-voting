// ============================================================================
// reconstructCatLineage.ts — CAT LineageProof for wasm buildCatCollateralSpend
// ============================================================================
//
// The wallet CAT coin's parent is almost always itself CAT-wrapped. Passing
// the parent's on-chain puzzle_hash as `parent_inner_puzzle_hash` is WRONG
// (that's the CAT outer). Sage simulates the spend → CLVM raise.
//
// Mirror `find_unspent_cat_coin` in `cli/.../live_integration_test.rs` and
// `Voter::reconstruct_cat_lineage` in the SDK: parse the parent spend with
// `Puzzle.parseChildCats` (chia-wallet-sdk-wasm) and take the matching child.

import { coinRecordByName, puzzleAndSolution } from "./coinset";
import type { CoinRecord } from "./coinset";
import { normalizeHex32 } from "./units";

function strip0x(h: string): string {
  return h.trim().replace(/^0x/i, "");
}

function withHex0x(fromChiaHex: string): string {
  const bare = strip0x(fromChiaHex).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(bare)) {
    throw new Error("Expected 32-byte hex from lineage field");
  }
  return `0x${bare}`;
}

function parentId32Hex(parentCoinInfo: string): string {
  const bare = strip0x(parentCoinInfo).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(bare)) {
    throw new Error("parentCoinInfo must be 32-byte hex");
  }
  return `0x${bare}`;
}

function bigintToSafeU64(b: bigint): number {
  if (b > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("Lineage parent_amount exceeds safe integer");
  }
  return Number(b);
}

/**
 * JSON `buildCatCollateralSpend` expects for `cat_input_lineage`
 * (camelCase → serde on the wasm side).
 */
export async function reconstructCatLineage(
  catCoin: CoinRecord,
  assetIdHex: string
): Promise<{
  parentParentCoinInfo: string;
  parentInnerPuzzleHash: string;
  parentAmount: number;
  assetIdHex: string;
}> {
  const tail = normalizeHex32(assetIdHex);
  if (!/^[0-9a-f]{64}$/.test(tail)) {
    throw new Error("Invalid CAT tail for lineage");
  }

  const parentId = parentId32Hex(catCoin.parentCoinInfo);
  const ps = await puzzleAndSolution(parentId);
  if (!ps) {
    throw new Error(
      "Parent coin has no puzzle+solution on chain (still unspent or not indexed). " +
        "CAT lineage cannot be derived."
    );
  }

  const parentRec = await coinRecordByName(parentId);
  if (!parentRec) {
    throw new Error("Parent coin record not found for CAT lineage.");
  }

  const chia = await import("chia-wallet-sdk-wasm");
  const clvm = new chia.Clvm();

  let puzzleProg: import("chia-wallet-sdk-wasm").Program | null = null;
  let solutionProg: import("chia-wallet-sdk-wasm").Program | null = null;

  try {
    puzzleProg = clvm.deserialize(
      chia.fromHex(strip0x(ps.puzzleHex))
    );
    solutionProg = clvm.deserialize(
      chia.fromHex(strip0x(ps.solutionHex))
    );

    const innerPuzzle = puzzleProg.puzzle();

    const parentCoin = new chia.Coin(
      chia.fromHex(strip0x(parentRec.parentCoinInfo)),
      chia.fromHex(strip0x(parentRec.puzzleHash)),
      BigInt(parentRec.amount)
    );

    const targetCoin = new chia.Coin(
      chia.fromHex(strip0x(catCoin.parentCoinInfo)),
      chia.fromHex(strip0x(catCoin.puzzleHash)),
      BigInt(catCoin.amount)
    );

    let children: import("chia-wallet-sdk-wasm").Cat[] | null | undefined;
    try {
      children = innerPuzzle.parseChildCats(parentCoin, solutionProg);
      if (!children || children.length === 0) {
        throw new Error(
          "Parent spend is not a CAT mint/transfer (parseChildCats empty). " +
            "Collateral coin may not be a standard wallet CAT."
        );
      }

      const targetId = targetCoin.coinId();
      let matched: import("chia-wallet-sdk-wasm").Cat | undefined;
      for (const c of children) {
        if (chia.bytesEqual(c.coin.coinId(), targetId)) {
          matched = c;
          break;
        }
      }
      if (!matched) {
        throw new Error(
          "Parent CAT spend does not create the selected collateral coin — lineage mismatch."
        );
      }

      const observed = normalizeHex32(chia.toHex(matched.assetId));
      if (observed !== tail) {
        throw new Error(
          `CAT asset id mismatch: collateral is ${observed.slice(0, 8)}… but election expects ${tail.slice(0, 8)}…`
        );
      }

      const lp = matched.lineageProof;
      if (!lp) {
        throw new Error("Matched CAT has no lineage proof.");
      }
      const innerPh = lp.parentInnerPuzzleHash;
      if (!innerPh) {
        throw new Error(
          "Lineage has no parent_inner_puzzle_hash (Eve genesis) — not supported for this path."
        );
      }

      return {
        parentParentCoinInfo: withHex0x(chia.toHex(lp.parentParentCoinInfo)),
        parentInnerPuzzleHash: withHex0x(chia.toHex(innerPh)),
        parentAmount: bigintToSafeU64(lp.parentAmount),
        assetIdHex: tail,
      };
    } finally {
      if (children) {
        for (const c of children) {
          try {
            c.free();
          } catch {
            /* ignore */
          }
        }
      }
      try {
        innerPuzzle.free();
      } catch {
        /* ignore */
      }
      try {
        parentCoin.free();
      } catch {
        /* ignore */
      }
      try {
        targetCoin.free();
      } catch {
        /* ignore */
      }
    }
  } finally {
    try {
      puzzleProg?.free();
    } catch {
      /* ignore */
    }
    try {
      solutionProg?.free();
    } catch {
      /* ignore */
    }
    try {
      clvm.free();
    } catch {
      /* ignore */
    }
  }
}
