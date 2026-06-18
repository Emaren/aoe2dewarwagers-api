# api-prodn Testing

## Goal

Keep this file brutally practical: how to run the backend safely, how to run tests, and what is currently broken or ambiguous.

## Runtime truth

- VPS repo path: `/mnt/HC_Volume_105319120/www-moved/AoE2DEWarWagers/api-prodn`
- service: `aoe2dewarwagers-api.service`
- bind: `127.0.0.1:4400`
- production exec:

```bash
/mnt/HC_Volume_105319120/www-moved/AoE2DEWarWagers/api-prodn/venv/bin/uvicorn app:app --host 127.0.0.1 --port 4400
```

## Local setup

The repo currently has multiple Python env hints. Do not assume `pytest` is on the default shell path.

Use an explicit venv:

```bash
cd /Users/tonyblum/projects/AoE2DEWarWagers/api-prodn
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If the project-specific environment already exists, use it explicitly instead of guessing:

```bash
source .venv-codex/bin/activate
```

## Local API run

The actual app entrypoint is `app:app`.

Suggested local run:

```bash
cd /Users/tonyblum/projects/AoE2DEWarWagers/api-prodn
source .venv-codex/bin/activate
uvicorn app:app --reload --host 127.0.0.1 --port 4400
```

Older scripts and README references still mention ports like `8002` and `8003`. Those are legacy/dev leftovers, not current production truth.

## Test commands

Preferred:

```bash
cd /Users/tonyblum/projects/AoE2DEWarWagers/api-prodn
source .venv-codex/bin/activate
pytest -q tests/test_replay_upload_metadata.py
```

Current parity gate:

```bash
pytest -q tests/test_replay_upload_metadata.py
# Expected: 36 passed
```

The broad legacy `pytest -q` run is not currently a hard gate. It includes
upstream parser tests that require the absent `tests/recs/small.mgz` fixture and
an async test plugin not installed in `.venv-codex`.

## Replay debugging notes

If `ENABLE_TRACE_LOGS=true`, local replay runs may generate:

- `*.trace`
- `trace.index`

That is expected during active replay debugging and is not, by itself, a failure condition.

Delete those artifacts when you want a cleaner repo snapshot, but leave logging on while building if the visibility is useful.

## Replay recency contract

Public recent-match surfaces should trust `played_at` from `/api/game_stats`.

Backend priority is:

- `played_on`
- filename-derived replay time, with local file mtime fallback when the filename has no parseable timestamp
- `created_at`
- `timestamp` as the final fallback only

`timestamp` remains a parse/update bookkeeping signal and should not be treated as “match was played at” for public ordering.

## What to verify before trusting results

Before trusting a future test pass, verify:

- the active venv
- installed test dependencies
- any async pytest plugin requirements
- replay fixture availability
- whether trace logging was on during the run
- whether you were testing live/non-final upload behavior or final settled replay behavior

## Current testing debt

Known current problems:

- in the default shell session, `pytest` was not found on PATH
- the broad legacy suite requires `tests/recs/small.mgz` and an async pytest plugin
- replay upload/live/final regression coverage should be clearer
- `tests/test_fast.py` skips missing replay fixtures instead of failing hard; current checked-in fixtures only cover `aoc-1.0.mgx`, `aoc-1.0c.mgx`, and `aok-2.0a.mgl`

## Suggested cleanup next

1. make one venv path canonical
2. document one exact passing test command
3. remove or clearly mark legacy run scripts using old ports
4. identify which tests are real gatekeepers for replay parsing and upload flows
5. add or document regression coverage for:
   - live upload behavior
   - final replay settlement behavior
   - parser edge cases on HD replays
6. restore the missing DE/HD replay fixtures used by `tests/test_fast.py`
