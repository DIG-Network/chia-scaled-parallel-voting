# CHIP companion documents

These Markdown files live next to the main draft **[CHIP_DRAFT.md](./CHIP_DRAFT.md)**—the CHIP body stays a higher-level overview; companion files add **protocol flow** and **puzzle-level** detail.

| Document | Contents |
|----------|----------|
| [CHIP_DRAFT.md](./CHIP_DRAFT.md) | Main CHIP draft (abstract through specification summary) |
| [chip-protocol-flow.md](./chip-protocol-flow.md) | End-to-end phases: ceremony → deploy → register → ballots → vote → finalize → deregister / release |
| [chip-ceremony.md](./chip-ceremony.md) | Ceremony Singleton, marker coins, voucher, `CANONICAL_MSG`, inner action tables |
| [chip-election-coins.md](./chip-election-coins.md) | `ElectionState`, Election / Ballot / Registration / Voting inner actions and state |
| [chip-witnesses-encoding.md](./chip-witnesses-encoding.md) | SPT definitions, vote modes, `vote_message`, eight public inputs, constants, announcements |
| [chip-groth16-clvm.md](./chip-groth16-clvm.md) | Groth16 + CLVM (CHIP-0011), finalize split with BLS, tolerance/threshold figures in `assets/` |
