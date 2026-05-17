# Parallel voting CHIP: companion documents

**Purpose:** These Markdown files accompany the draft CHIP in this directory. They split normative detail by topic so the main draft stays readable. **Relative links** between files (`./CHIP_DRAFT.md`, `./chip-protocol-flow.md`, …) stay valid when this folder is copied into the [Chia chips](https://github.com/Chia-Network/chips) repository (for example under `CHIPs/` next to the numbered CHIP or in a small subfolder).

**Reference implementation (executable spec):** [DIG-Network/chia-parallel-voting](https://github.com/DIG-Network/chia-parallel-voting), branch `main` (Rue puzzles, compiled CLVM, SDK, CLI, WASM, tests). Companion **figures** for [chip-groth16-clvm.md](./chip-groth16-clvm.md) are hosted in that repo’s [`assets/`](https://github.com/DIG-Network/chia-parallel-voting/tree/main/assets) tree.

---

## Document map

| Document | Contents |
| -------- | -------- |
| [CHIP_DRAFT.md](./CHIP_DRAFT.md) | Main CHIP text: preamble, abstract, motivation, specification summary, reference implementation, security, copyright |
| [chip-protocol-flow.md](./chip-protocol-flow.md) | Phases 0–5 (ceremony through exit); *Implementation* pointers into the reference repo |
| [chip-ceremony.md](./chip-ceremony.md) | Ceremony singleton, marker coin, voucher, inner-action table |
| [chip-election-coins.md](./chip-election-coins.md) | Election, Ballot, Registration, and Voting coins; inner actions and lineage |
| [chip-witnesses-encoding.md](./chip-witnesses-encoding.md) | Merkle rules, vote modes, `vote_message`, eight public inputs, announcements |
| [chip-groth16-clvm.md](./chip-groth16-clvm.md) | Groth16 + CLVM finalize path, soundness intuition, **informative** BLS12-377 note, figures |

**Tests and vectors:** see **Test plan** in [CHIP_DRAFT.md](./CHIP_DRAFT.md) and [`sdk/tests/`](https://github.com/DIG-Network/chia-parallel-voting/tree/main/sdk/tests) in the reference implementation.
