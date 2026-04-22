# mgz DE Parser Support Issue Packet

## Summary

Newer Age of Empires II: Definitive Edition recorded games from build `v101.103.39862.0` are not parseable by the tested `mgz` releases. Older local DE replays from `v101.103.2359.0` parse cleanly through the same product parser path, so this looks like a replay-format support gap for newer DE files rather than an upload wrapper or file-extension issue.

The product now has a fallback rail: final uploads are preserved as `watcher_final_unparsed` or `watcher_final_metadata` rows when parser support fails. That keeps feeds honest, but parser support is still needed for trusted rosters, map details, winners, and bet-arming eligibility.

## Failing Replay

- Replay filename: `MP Replay v101.103.39862.0 @2026.04.22 024314 (4).aoe2record`
- SHA256: `8059fe555d7359aa23f7b36152f01e67b99c67e28b2d9671e2cfea0e00a65368`
- File size: `1154519` bytes
- Game version in filename/session data: `101.103.39862.0`
- DE build in `Age2SessionData.txt`: `170934`

## Working Comparison

- Older local DE replay version: `v101.103.2359.0`
- These 2025 DE replays parse cleanly through the same API parser path.
- The failure appears tied to the newer `v101.103.39862.0` replay variant.

## Tested Parser Versions

- `mgz 1.8.27`: fails
- `mgz 1.8.51`: fails

## Failure Family

All three parser rails fail on the same replay:

- Standard header parse
- Fast header parse
- Summary/full fallback

Observed failure shape:

- On `mgz 1.8.27`, standard parse dies under `de -> de -> players` with mapping/range errors. Fast header parse also fails. Summary/full fallback also fails.
- On `mgz 1.8.51`, standard parse still dies under `de -> de -> players`, now around `players -> ai_type`. Fast header parse still fails. Summary/full fallback still fails.
- Product-level result: `winner = Unknown`, `completed = False`, `players = 0`, `player_extraction_source = no_players`.

## Product Fallback Now In Place

AoE2DEWarWagers no longer drops these final uploads:

- Bare parser-blind finals persist as `parse_reason = watcher_final_unparsed`.
- Parser-blind finals with watcher runtime context persist as `parse_reason = watcher_final_metadata`.
- Watcher metadata is explicitly not parser truth and does not arm bets.
- A later parser-trusted result for the same replay hash upgrades the same visible final row instead of creating a duplicate.

## Maintainer Ask

Please investigate DE `v101.103.39862.0` recorded-game header/player parsing, especially the `de -> de -> players -> ai_type` area. The failing replay is small enough to share privately if needed.
