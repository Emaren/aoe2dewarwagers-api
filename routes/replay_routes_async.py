from fastapi import APIRouter, HTTPException, Depends, Query, Header, UploadFile, File, Form
from pydantic import BaseModel, Field
from sqlalchemy import select
from db.db import get_db
from datetime import datetime
import logging
import os
from typing import Optional, Tuple
from pathlib import Path
import tempfile
import hashlib
import hmac
import base64
import re
import json
from sqlalchemy import text, update

# Prefer full model set if present (User/ApiKey added in recent migration)
try:
    from db.models import GameStats, User, ApiKey, ReplayParseAttempt
except Exception:  # pragma: no cover
    from db.models import GameStats  # type: ignore
    User = None  # type: ignore
    ApiKey = None  # type: ignore
    ReplayParseAttempt = None  # type: ignore

from utils.replay_parser import parse_replay_full_with_error, hash_replay_file

router = APIRouter(prefix="/api", tags=["replay"])

INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY")  # optional; if set, enforces auth for uploads
MAX_REPLAY_UPLOAD_BYTES = int(os.getenv("MAX_REPLAY_UPLOAD_BYTES", str(250 * 1024 * 1024)))
SUPERSEDED_PARSE_REASON = "superseded_by_later_upload"
PLACEHOLDER_LIVE_PARSE_REASON = "watcher_live_pending_parse"
FINAL_UNPARSED_PARSE_REASON = "watcher_final_unparsed"
FINAL_METADATA_PARSE_REASON = "watcher_final_metadata"
WATCHER_METADATA_SCHEMA = "aoe2dewarwagers.watcher_final_metadata.v1"
WATCHER_METADATA_MAX_CHARS = 64_000

WATCHER_KEY_RE = re.compile(r"^wolo_([a-f0-9]{12})_(.+)$", re.IGNORECASE)


async def require_internal_key(
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key")
):
    # Internal-only routes still require the internal key if configured.
    if INTERNAL_API_KEY and x_api_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True


class ParseReplayRequest(BaseModel):
    replay_file: str
    replay_hash: str
    parse_iteration: int = 0
    is_final: bool = False
    game_version: str | None = None
    map: dict | None = None
    map_name: str = "Unknown"
    map_size: str = "Unknown"
    game_type: str | None = None
    duration: int = 0
    game_duration: int | None = None
    winner: str = "Unknown"
    players: list = Field(default_factory=list)
    event_types: list = Field(default_factory=list)
    key_events: dict = Field(default_factory=dict)
    played_on: str | None = None
    disconnect_detected: bool | None = None
    parse_source: str | None = None
    parse_reason: str | None = None
    original_filename: str | None = None


def _safe_iso_datetime(value: str | None):
    if not value:
        return None

    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _clean_detail(value: str | None, fallback: str | None = None):
    cleaned = " ".join((value or fallback or "").split()).strip()
    return cleaned[:255] if cleaned else None


def _extract_platform_match_id(value: object) -> str | None:
    if not isinstance(value, dict):
        return None

    candidate = value.get("platform_match_id")
    if not isinstance(candidate, str):
        return None

    cleaned = candidate.strip()
    return cleaned or None


def _parse_bool_header(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on", "final"}:
        return True
    if normalized in {"0", "false", "no", "n", "off", "live"}:
        return False
    return default


def _parse_positive_int_header(value: Optional[str], default: int = 1) -> int:
    if value is None:
        return default

    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default

    return parsed if parsed > 0 else default


def _derive_upload_parse_metadata(
    *,
    upload_mode: str,
    is_final: bool,
    requested_source: Optional[str],
    requested_reason: Optional[str],
    parsed_reason: Optional[str],
) -> Tuple[str, str]:
    parse_source = _clean_detail(requested_source)
    parse_reason = _clean_detail(requested_reason)
    parsed_reason_clean = _clean_detail(parsed_reason)
    generic_requested_reason = parse_reason in {
        None,
        "watcher_or_browser",
        "watcher_final_submission",
        "watcher_live_iteration",
    }

    if not parse_source:
        if upload_mode == "watcher":
            parse_source = "watcher_final" if is_final else "watcher_live"
        else:
            parse_source = "file_upload"

    if parsed_reason_clean and parsed_reason_clean != "watcher_or_browser" and generic_requested_reason:
        parse_reason = parsed_reason_clean
    elif not parse_reason:
        if upload_mode == "watcher":
            parse_reason = "watcher_final_submission" if is_final else "watcher_live_iteration"
        else:
            parse_reason = "watcher_or_browser"

    return parse_source, parse_reason


def _map_payload(data: ParseReplayRequest):
    map_payload = data.map if isinstance(data.map, dict) else {}
    map_name = data.map_name
    map_size = data.map_size

    if map_name == "Unknown":
        map_name = map_payload.get("name", "Unknown")
    if map_size == "Unknown":
        map_size = map_payload.get("size", "Unknown")

    return {"name": map_name, "size": map_size}


def _norm_name(s: str) -> str:
    return " ".join((s or "").strip().split()).lower()


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _verify_pbkdf2(secret: str, stored: str) -> bool:
    """
    stored format: pbkdf2_sha256$<iters>$<salt_b64url>$<dk_b64url>
    """
    try:
        algo, iters_s, salt_s, dk_s = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        salt = _b64url_decode(salt_s)
        expected = _b64url_decode(dk_s)
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            secret.encode("utf-8"),
            salt,
            iters,
            dklen=len(expected),
        )
        return hmac.compare_digest(derived, expected)
    except Exception:
        return False


def _verify_key_hash(x_api_key: str, stored_hash: str) -> bool:
    """
    Supports two storage formats:
      - pbkdf2_sha256$... (legacy/secure)
      - 64-char sha256 hex of the full key (current simple mode)
    """
    if not stored_hash:
        return False
    if stored_hash.startswith("pbkdf2_sha256$"):
        # For PBKDF2 format, secret = entire key or just the secret?
        # Our PBKDF2 variant (if used) hashes the "secret" portion; to be safe, verify both.
        m = WATCHER_KEY_RE.match(x_api_key)
        if m and _verify_pbkdf2(m.group(2), stored_hash):
            return True
        return _verify_pbkdf2(x_api_key, stored_hash)

    # Otherwise treat as sha256 hex of full api key
    if len(stored_hash) == 64 and all(c in "0123456789abcdef" for c in stored_hash.lower()):
        return hmac.compare_digest(_sha256_hex(x_api_key), stored_hash.lower())

    return False


async def _resolve_upload_identity(db, x_api_key: Optional[str], claimed_uid: str) -> Tuple[str, str]:
    """
    Returns (uploader_uid, mode) where mode is:
      - "internal" when INTERNAL_API_KEY is used
      - "watcher" when a watcher key binds to a user
      - "dev" when INTERNAL_API_KEY is not set and no x-api-key provided
    """
    # 1) Internal trusted key path
    if INTERNAL_API_KEY and x_api_key == INTERNAL_API_KEY:
        return (claimed_uid or "system"), "internal"

    # 2) If internal key configured, require either internal or watcher key
    if INTERNAL_API_KEY and not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    # 3) Dev convenience: allow missing key if no internal key configured
    if not x_api_key:
        return (claimed_uid or "system"), "dev"

    # 4) Watcher key path: wolo_<prefix>_<secret>
    if ApiKey is None or User is None:
        raise HTTPException(status_code=500, detail="Watcher key support not available (models not loaded)")

    m = WATCHER_KEY_RE.match(x_api_key.strip())
    if not m:
        raise HTTPException(status_code=401, detail="Invalid API key")

    prefix = m.group(1).lower()

    res = await db.execute(
        select(ApiKey).where(
            ApiKey.key_prefix == prefix,
            ApiKey.revoked_at.is_(None),
            ApiKey.kind == "watcher",
        )
    )
    api_key = res.scalars().first()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not _verify_key_hash(x_api_key.strip(), api_key.key_hash):
        raise HTTPException(status_code=401, detail="Invalid API key")

    ures = await db.execute(select(User).where(User.id == api_key.user_id))
    user = ures.scalars().first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Touch last_used_at
    api_key.last_used_at = datetime.utcnow()

    return user.uid, "watcher"


async def _load_user_by_uid(db, uid: Optional[str]):
    if User is None or not uid or uid == "system":
        return None
    res = await db.execute(select(User).where(User.uid == uid))
    return res.scalars().first()


async def _record_parse_attempt(
    db,
    *,
    user_uid: Optional[str],
    replay_hash: Optional[str],
    original_filename: Optional[str],
    parse_source: str,
    status: str,
    detail: Optional[str],
    upload_mode: Optional[str],
    file_size_bytes: Optional[int],
    game_stats_id: Optional[int] = None,
    played_on=None,
):
    if ReplayParseAttempt is None:
        return

    db.add(
        ReplayParseAttempt(
            user_uid=user_uid,
            replay_hash=replay_hash,
            original_filename=original_filename,
            parse_source=parse_source,
            status=status,
            detail=_clean_detail(detail),
            upload_mode=upload_mode,
            file_size_bytes=file_size_bytes,
            game_stats_id=game_stats_id,
            played_on=played_on,
        )
    )


def _is_placeholder_live_game(game) -> bool:
    return bool(game) and not bool(getattr(game, "is_final", False)) and getattr(
        game, "parse_reason", None
    ) == PLACEHOLDER_LIVE_PARSE_REASON


async def _load_existing_placeholder_live_game(
    db,
    uploader_uid: Optional[str],
    original_filename: Optional[str],
):
    if not original_filename:
        return None

    result = await db.execute(
        select(GameStats)
        .where(GameStats.user_uid == (uploader_uid or "system"))
        .where(GameStats.original_filename == original_filename)
        .where(GameStats.is_final.is_(False))
        .where(GameStats.parse_reason == PLACEHOLDER_LIVE_PARSE_REASON)
        .order_by(GameStats.id.desc())
    )
    return result.scalars().first()


def _apply_parsed_upload_to_game(
    game,
    *,
    uploader_uid: Optional[str],
    replay_hash: str,
    original_name: str,
    parsed: dict,
    map_payload: dict,
    duration: int,
    winner: str,
    players: list,
    event_types: list,
    key_events: dict,
    parse_iteration: int,
    is_final_upload: bool,
    disconnect_detected: bool,
    parse_source: str,
    parse_reason: str,
    played_on,
):
    game.user_uid = uploader_uid or "system"
    game.replay_file = original_name
    game.replay_hash = replay_hash
    game.game_version = parsed.get("game_version")
    game.map = map_payload
    game.game_type = parsed.get("game_type")
    game.duration = duration
    game.game_duration = duration
    game.winner = winner
    game.players = players
    game.event_types = event_types
    game.key_events = key_events
    game.parse_iteration = parse_iteration
    game.is_final = is_final_upload
    game.disconnect_detected = disconnect_detected
    game.parse_source = parse_source
    game.parse_reason = parse_reason
    game.original_filename = original_name
    game.timestamp = datetime.utcnow()
    if played_on is not None:
        game.played_on = played_on


async def _load_existing_final_by_platform_match_id(db, platform_match_id: Optional[str]):
    if not platform_match_id:
        return None

    result = await db.execute(
        select(GameStats)
        .where(GameStats.is_final.is_(True))
        .where(text("key_events->>'platform_match_id' = :platform_match_id"))
        .params(platform_match_id=platform_match_id)
        .order_by(GameStats.created_at.asc(), GameStats.id.asc())
    )
    return result.scalars().first()


async def _load_existing_final_by_replay_hash(db, replay_hash: str):
    result = await db.execute(
        select(GameStats).where(
            GameStats.replay_hash == replay_hash,
            GameStats.is_final.is_(True),
        )
    )
    return result.scalars().first()


def _match_uploader_player(players: list, user, claimed_name: Optional[str]):
    steam_id = str(getattr(user, "steam_id", "") or "").strip()
    if steam_id:
        for player in players:
            if str(player.get("user_id", "") or "").strip() == steam_id:
                return player

    candidate_names = {
        _norm_name(value)
        for value in [
            claimed_name,
            getattr(user, "in_game_name", None),
            getattr(user, "steam_persona_name", None),
        ]
        if value
    }

    for player in players:
        if _norm_name(str(player.get("name", "") or "")) in candidate_names:
            return player

    return None


def _infer_incomplete_uploader_outcome(parsed: dict, user, claimed_name: Optional[str]):
    winner = parsed.get("winner") or "Unknown"
    players = parsed.get("players") if isinstance(parsed.get("players"), list) else []
    completed = parsed.get("completed")
    key_events = parsed.get("key_events") if isinstance(parsed.get("key_events"), dict) else {}

    if winner not in {"", None, "Unknown"}:
        return None
    if user is None:
        return None
    if parsed.get("parse_reason") == "hd_early_exit_under_60s" or key_events.get("no_rated_result"):
        return None
    if completed is not False:
        return None
    if len(players) != 2:
        return None
    if not key_events.get("rated"):
        return None

    uploader_player = _match_uploader_player(players, user, claimed_name)
    if not uploader_player:
        return None

    uploader_name = str(uploader_player.get("name", "") or "").strip()
    opponents = [
        dict(player)
        for player in players
        if _norm_name(str(player.get("name", "") or "")) != _norm_name(uploader_name)
    ]
    if len(opponents) != 1:
        return None

    inferred_winner = str(opponents[0].get("name", "") or "").strip()
    if not inferred_winner:
        return None

    patched_players = []
    for player in players:
        updated = dict(player)
        if _norm_name(str(updated.get("name", "") or "")) == _norm_name(inferred_winner):
            updated["winner"] = True
        elif _norm_name(str(updated.get("name", "") or "")) == _norm_name(uploader_name):
            updated["winner"] = False
        patched_players.append(updated)

    key_events = dict(parsed.get("key_events") or {})
    key_events["winner_inference"] = {
        "type": "uploader_incomplete_1v1_opponent",
        "uploader_player": uploader_name,
        "inferred_winner": inferred_winner,
    }

    return {
        "winner": inferred_winner,
        "players": patched_players,
        "disconnect_detected": True,
        "parse_reason": "watcher_inferred_opponent_win_on_incomplete_1v1",
        "key_events": key_events,
    }


def _has_reliable_final_signal(parsed: dict, inferred_outcome: Optional[dict] = None):
    if inferred_outcome:
        return True

    key_events = parsed.get("key_events") if isinstance(parsed.get("key_events"), dict) else {}
    if key_events.get("completed") is True:
        return True
    if key_events.get("postgame_available") is True:
        return True
    if key_events.get("has_achievements") is True:
        return True
    if _coerce_positive_int(key_events.get("player_score_count")) > 0:
        return True

    winner = parsed.get("winner")
    if isinstance(winner, str):
        cleaned_winner = winner.strip()
        if cleaned_winner and cleaned_winner != "Unknown":
            return True

    player_source = str(key_events.get("player_extraction_source") or "").strip()
    player_count = _coerce_positive_int(key_events.get("player_count"))
    duration = _coerce_positive_int(parsed.get("duration") or parsed.get("game_duration"))
    if player_source in {"header_fallback", "fast_header_fallback"} and player_count >= 2 and duration >= 60:
        return True

    return False


def _normalize_live_disconnect_detected(
    is_final_upload: bool,
    disconnect_detected: bool,
    key_events: dict,
):
    if is_final_upload:
        return disconnect_detected

    if not isinstance(key_events, dict):
        return False

    if key_events.get("completed") is True:
        return disconnect_detected

    return False


def _coerce_positive_int(value):
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        numeric = int(value)
        return numeric if numeric > 0 else 0
    if isinstance(value, str):
        try:
            numeric = int(value.strip())
            return numeric if numeric > 0 else 0
        except ValueError:
            return 0
    return 0


def _coerce_optional_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
    return None


def _clean_metadata_string(value, max_length: int = 255):
    if value is None:
        return None
    cleaned = " ".join(str(value).split()).strip()
    return cleaned[:max_length] if cleaned else None


def _metadata_datetime(value):
    if isinstance(value, str):
        return _safe_iso_datetime(value)
    return None


def _parse_watcher_metadata(raw_metadata: Optional[str], replay_hash: str):
    if not raw_metadata:
        return None, None

    if len(raw_metadata) > WATCHER_METADATA_MAX_CHARS:
        return None, "watcher metadata payload too large"

    try:
        parsed = json.loads(raw_metadata)
    except json.JSONDecodeError as exc:
        return None, f"invalid watcher metadata json: {exc.msg}"

    if not isinstance(parsed, dict):
        return None, "watcher metadata must be a JSON object"

    metadata_hash = _clean_metadata_string(parsed.get("replay_hash"), 80)
    if metadata_hash and metadata_hash.lower() != replay_hash.lower():
        return None, "watcher metadata replay_hash did not match uploaded file"

    return parsed, None


def _normalize_metadata_players(metadata: dict, winner_name: Optional[str], winner_reliable: bool):
    raw_players = metadata.get("players")
    if not isinstance(raw_players, list):
        return []

    players = []
    seen = set()
    for index, raw_player in enumerate(raw_players, start=1):
        if not isinstance(raw_player, dict):
            continue

        name = _clean_metadata_string(
            raw_player.get("name")
            or raw_player.get("player_name")
            or raw_player.get("profile_name"),
            100,
        )
        if not name:
            continue

        norm = _norm_name(name)
        if norm in seen:
            continue
        seen.add(norm)

        player = {
            "name": name,
            "source": "watcher_metadata",
        }
        for target_key, source_keys in {
            "civilization": ("civilization", "civ", "civilization_name"),
            "color": ("color", "color_name"),
            "team": ("team", "team_id"),
            "user_id": ("user_id", "steam_id", "profile_id"),
        }.items():
            for source_key in source_keys:
                value = _clean_metadata_string(raw_player.get(source_key), 100)
                if value:
                    player[target_key] = value
                    break

        slot = _coerce_positive_int(
            raw_player.get("slot") or raw_player.get("number") or raw_player.get("player_number")
        )
        player["number"] = slot or index

        raw_winner = _coerce_optional_bool(raw_player.get("winner"))
        if winner_reliable:
            if winner_name:
                player["winner"] = _norm_name(name) == _norm_name(winner_name)
            elif raw_winner is not None:
                player["winner"] = raw_winner
        else:
            player["winner"] = None

        players.append(player)

    return players


def _normalize_watcher_metadata(
    metadata: Optional[dict],
    *,
    replay_hash: str,
    original_name: str,
    uploader_uid: Optional[str],
    file_size_bytes: Optional[int],
):
    if not isinstance(metadata, dict):
        return None

    schema = _clean_metadata_string(metadata.get("schema"), 120)
    version = _coerce_positive_int(metadata.get("version")) or 1
    trust = metadata.get("trust") if isinstance(metadata.get("trust"), dict) else {}
    winner_payload = metadata.get("winner")
    winner_name = None
    winner_reliable = False
    if isinstance(winner_payload, str):
        winner_name = _clean_metadata_string(winner_payload, 100)
    elif isinstance(winner_payload, dict):
        winner_name = _clean_metadata_string(
            winner_payload.get("name") or winner_payload.get("player_name") or winner_payload.get("value"),
            100,
        )
        winner_reliable = _coerce_optional_bool(
            winner_payload.get("reliable") or winner_payload.get("trusted")
        ) is True
    winner_reliable = winner_reliable or _coerce_optional_bool(
        trust.get("winner") or trust.get("winner_reliable")
    ) is True
    if not winner_reliable:
        winner_name = None

    players = _normalize_metadata_players(metadata, winner_name, winner_reliable)
    player_count = _coerce_positive_int(metadata.get("player_count") or metadata.get("players_count"))
    if not player_count and players:
        player_count = len(players)

    map_metadata = metadata.get("map") if isinstance(metadata.get("map"), dict) else {}
    map_name = _clean_metadata_string(map_metadata.get("name") or metadata.get("map_name"), 120)
    map_size = _clean_metadata_string(map_metadata.get("size") or metadata.get("map_size"), 80)
    mode = _clean_metadata_string(
        metadata.get("mode") or metadata.get("game_mode") or metadata.get("game_type"),
        80,
    )
    rated = _coerce_optional_bool(metadata.get("rated") if "rated" in metadata else metadata.get("is_rated"))
    started_at = _metadata_datetime(metadata.get("started_at") or metadata.get("startedAt"))
    ended_at = _metadata_datetime(metadata.get("ended_at") or metadata.get("endedAt"))
    uploaded_at = _metadata_datetime(metadata.get("uploaded_at") or metadata.get("uploadedAt"))
    session_id = _clean_metadata_string(metadata.get("session_id") or metadata.get("sessionId"), 120)
    lobby_id = _clean_metadata_string(
        metadata.get("lobby_id") or metadata.get("lobbyId") or metadata.get("match_id"),
        120,
    )
    filename = _clean_metadata_string(
        metadata.get("filename") or metadata.get("original_filename") or original_name,
        255,
    )
    metadata_sources = metadata.get("metadata_sources")
    if not isinstance(metadata_sources, list):
        metadata_sources = [metadata.get("metadata_source") or "watcher_metadata"]
    metadata_sources = [
        source
        for source in (
            _clean_metadata_string(source, 80)
            for source in metadata_sources
        )
        if source
    ]
    if not metadata_sources:
        metadata_sources = ["watcher_metadata"]

    trusted_player_data = (
        _coerce_optional_bool(trust.get("trusted_player_data") or trust.get("player_data")) is True
        and len(players) >= 2
    )

    return {
        "schema": schema or WATCHER_METADATA_SCHEMA,
        "version": version,
        "replay_hash": replay_hash,
        "watcher_uid": _clean_metadata_string(metadata.get("watcher_uid"), 120),
        "uploader_uid": uploader_uid,
        "session_id": session_id,
        "lobby_id": lobby_id,
        "filename": filename or original_name,
        "started_at": started_at,
        "ended_at": ended_at,
        "uploaded_at": uploaded_at,
        "file_size_bytes": _coerce_positive_int(metadata.get("file_size_bytes")) or file_size_bytes,
        "players": players,
        "player_count": player_count or 0,
        "map": {
            "name": map_name or "Unknown",
            "size": map_size or "Unknown",
        },
        "game_type": mode,
        "rated": rated,
        "winner": winner_name or "Unknown",
        "winner_reliable": bool(winner_name and winner_reliable),
        "trusted_player_data": trusted_player_data,
        "metadata_sources": metadata_sources,
        "local_sidecar_filename": _clean_metadata_string(metadata.get("local_sidecar_filename"), 255),
    }


def _has_meaningful_watcher_metadata(normalized_metadata: Optional[dict]):
    if not isinstance(normalized_metadata, dict):
        return False

    return any(
        [
            normalized_metadata.get("session_id"),
            normalized_metadata.get("lobby_id"),
            normalized_metadata.get("started_at"),
            normalized_metadata.get("ended_at"),
            normalized_metadata.get("uploaded_at"),
            normalized_metadata.get("file_size_bytes"),
            normalized_metadata.get("player_count"),
            normalized_metadata.get("players"),
            normalized_metadata.get("map", {}).get("name") not in {None, "", "Unknown"},
        ]
    )


def _build_replay_parser_failure_snapshot(parsed: Optional[dict], parser_error: Optional[str]):
    parsed_payload = parsed if isinstance(parsed, dict) else {}
    key_events = parsed_payload.get("key_events") if isinstance(parsed_payload.get("key_events"), dict) else {}

    return {
        "trusted": False,
        "winner": parsed_payload.get("winner") or "Unknown",
        "completed": parsed_payload.get("completed"),
        "parse_reason": parsed_payload.get("parse_reason"),
        "players_count": len(parsed_payload.get("players")) if isinstance(parsed_payload.get("players"), list) else 0,
        "player_extraction_source": key_events.get("player_extraction_source"),
        "player_extraction_error": _extract_unparsed_final_parser_error(parsed_payload, parser_error),
    }


def _build_metadata_final_game_kwargs(
    *,
    parsed: Optional[dict],
    normalized_metadata: dict,
    parse_source: str,
    parser_error: Optional[str],
    parse_iteration: int,
):
    parsed_payload = parsed if isinstance(parsed, dict) else {}
    raw_duration = parsed_payload.get("duration") or parsed_payload.get("game_duration") or 0
    duration = _coerce_positive_int(raw_duration)
    started_at = normalized_metadata.get("started_at")
    ended_at = normalized_metadata.get("ended_at")
    if duration <= 0 and started_at and ended_at:
        try:
            duration = max(0, int((ended_at - started_at).total_seconds()))
        except TypeError:
            duration = 0

    players = normalized_metadata.get("players") if isinstance(normalized_metadata.get("players"), list) else []
    player_count = len(players) or _coerce_positive_int(normalized_metadata.get("player_count"))
    trusted_player_data = bool(normalized_metadata.get("trusted_player_data") and len(players) >= 2)
    winner = normalized_metadata.get("winner") if normalized_metadata.get("winner_reliable") else "Unknown"
    if not winner:
        winner = "Unknown"

    replay_parser = _build_replay_parser_failure_snapshot(parsed_payload, parser_error)
    key_events = {
        "completed": False,
        "postgame_available": False,
        "has_achievements": False,
        "has_scores": False,
        "player_score_count": 0,
        "achievement_player_count": 0,
        "player_count": player_count,
        "player_data_source": "watcher_metadata",
        "player_extraction_source": "watcher_metadata" if players else "no_players",
        "player_extraction_error": replay_parser["player_extraction_error"],
        "trusted_player_data": trusted_player_data,
        "replay_parser_trust": False,
        "bet_arming_eligible": False,
        "watcher_final_metadata": True,
        "final_unparsed": False,
        "watcher_metadata": {
            "schema": normalized_metadata.get("schema"),
            "version": normalized_metadata.get("version"),
            "sources": normalized_metadata.get("metadata_sources"),
            "session_id": normalized_metadata.get("session_id"),
            "lobby_id": normalized_metadata.get("lobby_id"),
            "filename": normalized_metadata.get("filename"),
            "started_at": started_at.isoformat() if started_at else None,
            "ended_at": ended_at.isoformat() if ended_at else None,
            "uploaded_at": normalized_metadata.get("uploaded_at").isoformat()
            if normalized_metadata.get("uploaded_at")
            else None,
            "file_size_bytes": normalized_metadata.get("file_size_bytes"),
            "player_count": player_count,
            "players_known": bool(players),
            "map_known": normalized_metadata.get("map", {}).get("name") not in {None, "", "Unknown"},
            "rated": normalized_metadata.get("rated"),
            "winner_reliable": bool(normalized_metadata.get("winner_reliable")),
            "trusted_player_data": trusted_player_data,
            "local_sidecar_filename": normalized_metadata.get("local_sidecar_filename"),
        },
        "replay_parser": replay_parser,
    }
    if normalized_metadata.get("rated") is not None:
        key_events["rated"] = normalized_metadata.get("rated")

    return {
        "game_version": parsed_payload.get("game_version"),
        "map": normalized_metadata.get("map") or {"name": "Unknown", "size": "Unknown"},
        "game_type": normalized_metadata.get("game_type") or parsed_payload.get("game_type"),
        "duration": duration,
        "game_duration": duration,
        "winner": winner,
        "players": players,
        "event_types": parsed_payload.get("event_types")
        if isinstance(parsed_payload.get("event_types"), list)
        else [],
        "key_events": key_events,
        "parse_iteration": parse_iteration,
        "is_final": True,
        "disconnect_detected": False,
        "parse_source": _clean_detail(parse_source, "watcher_final") or "watcher_final",
        "parse_reason": FINAL_METADATA_PARSE_REASON,
        "played_on": started_at,
    }


def _clean_key_event_error(value: Optional[str], fallback: Optional[str] = None):
    raw = value if value is not None else fallback
    cleaned = " ".join(str(raw or "").split()).strip()
    if not cleaned:
        return "unknown replay parser failure"
    return cleaned[:1000]


def _extract_unparsed_final_parser_error(parsed: Optional[dict], parser_error: Optional[str]):
    key_events = parsed.get("key_events") if isinstance(parsed, dict) else {}
    if not isinstance(key_events, dict):
        key_events = {}

    details = []
    for key in (
        "player_extraction_error",
        "summary_init_error",
        "standard_header_error",
        "fast_header_error",
        "parser_error",
        "parse_error",
    ):
        value = key_events.get(key)
        if value:
            details.append(f"{key}: {_clean_key_event_error(str(value))}")

    if details:
        return _clean_key_event_error("; ".join(details))

    return _clean_key_event_error(parser_error, "replay parser returned no trusted player data")


def _build_unparsed_final_game_kwargs(
    *,
    parsed: Optional[dict],
    parse_source: str,
    parser_error: Optional[str],
    parse_iteration: int,
):
    parsed_payload = parsed if isinstance(parsed, dict) else {}
    map_info = parsed_payload.get("map") if isinstance(parsed_payload.get("map"), dict) else {}
    raw_duration = parsed_payload.get("duration") or parsed_payload.get("game_duration") or 0
    duration = _coerce_positive_int(raw_duration)
    raw_played_on = parsed_payload.get("played_on")
    key_events = (
        dict(parsed_payload.get("key_events"))
        if isinstance(parsed_payload.get("key_events"), dict)
        else {}
    )
    key_events.pop("completion_source", None)
    key_events.pop("winner_inference", None)
    key_events.update(
        {
            "completed": False,
            "postgame_available": False,
            "has_achievements": False,
            "has_scores": False,
            "player_score_count": 0,
            "achievement_player_count": 0,
            "player_count": 0,
            "player_extraction_source": "no_players",
            "player_extraction_error": _extract_unparsed_final_parser_error(
                parsed_payload,
                parser_error,
            ),
            "trusted_player_data": False,
            "final_unparsed": True,
        }
    )

    return {
        "game_version": parsed_payload.get("game_version"),
        "map": {
            "name": map_info.get("name", "Unknown"),
            "size": map_info.get("size", "Unknown"),
        },
        "game_type": parsed_payload.get("game_type"),
        "duration": duration,
        "game_duration": duration,
        "winner": "Unknown",
        "players": [],
        "event_types": parsed_payload.get("event_types")
        if isinstance(parsed_payload.get("event_types"), list)
        else [],
        "key_events": key_events,
        "parse_iteration": parse_iteration,
        "is_final": True,
        "disconnect_detected": False,
        "parse_source": _clean_detail(parse_source, "watcher_final") or "watcher_final",
        "parse_reason": FINAL_UNPARSED_PARSE_REASON,
        "played_on": _safe_iso_datetime(raw_played_on if isinstance(raw_played_on, str) else None),
    }


async def _store_unparsed_final_upload(
    db,
    *,
    uploader_uid: Optional[str],
    replay_hash: str,
    original_name: str,
    parsed: Optional[dict],
    parse_source: str,
    parser_error: Optional[str],
    parse_iteration: int,
    upload_mode: str,
    file_size_bytes: Optional[int],
):
    game_kwargs = _build_unparsed_final_game_kwargs(
        parsed=parsed,
        parse_source=parse_source,
        parser_error=parser_error,
        parse_iteration=parse_iteration,
    )

    existing_final_game = await _load_existing_final_by_replay_hash(db, replay_hash)
    if existing_final_game:
        await _record_parse_attempt(
            db,
            user_uid=uploader_uid,
            replay_hash=replay_hash,
            original_filename=original_name,
            parse_source=game_kwargs["parse_source"],
            status="duplicate_final",
            detail="Replay already stored as final. Skipped.",
            upload_mode=upload_mode,
            file_size_bytes=file_size_bytes,
            game_stats_id=existing_final_game.id,
            played_on=game_kwargs["played_on"],
        )
        await db.commit()
        return {
            "message": "Replay already stored as final. Skipped.",
            "replay_hash": replay_hash,
            "uploader_uid": uploader_uid,
            "upload_mode": upload_mode,
            "is_final": True,
            "unparsed_final": existing_final_game.parse_reason == FINAL_UNPARSED_PARSE_REASON,
        }

    previous_versions = []
    if original_name and uploader_uid and uploader_uid != "system":
        prior = await db.execute(
            select(GameStats.id, GameStats.replay_hash).where(
                GameStats.user_uid == uploader_uid,
                GameStats.original_filename == original_name,
                GameStats.is_final.is_(True),
            )
        )
        previous_versions = [
            row.id
            for row in prior
            if row.replay_hash != replay_hash
        ]

    game = GameStats(
        user_uid=uploader_uid or "system",
        replay_file=original_name,
        replay_hash=replay_hash,
        original_filename=original_name,
        **game_kwargs,
    )
    db.add(game)
    await db.flush()

    if previous_versions:
        await db.execute(
            update(GameStats)
            .where(GameStats.id.in_(previous_versions))
            .values(
                is_final=False,
                parse_reason=SUPERSEDED_PARSE_REASON,
            )
        )

    await _record_parse_attempt(
        db,
        user_uid=uploader_uid,
        replay_hash=replay_hash,
        original_filename=original_name,
        parse_source=game_kwargs["parse_source"],
        status="stored_unparsed_final",
        detail="Final replay stored without trusted player data because replay parsing failed.",
        upload_mode=upload_mode,
        file_size_bytes=file_size_bytes,
        game_stats_id=game.id,
        played_on=game_kwargs["played_on"],
    )
    await db.commit()
    return {
        "message": "Final replay stored without trusted player data.",
        "replay_hash": replay_hash,
        "winner": "Unknown",
        "players_count": 0,
        "uploader_uid": uploader_uid,
        "upload_mode": upload_mode,
        "parse_iteration": parse_iteration,
        "is_final": True,
        "pending_parse": False,
        "unparsed_final": True,
        "parse_reason": FINAL_UNPARSED_PARSE_REASON,
    }


def _apply_final_game_kwargs(game, *, uploader_uid: Optional[str], original_name: str, replay_hash: str, game_kwargs: dict):
    game.user_uid = uploader_uid or getattr(game, "user_uid", None) or "system"
    game.replay_file = original_name
    game.replay_hash = replay_hash
    game.original_filename = original_name
    game.game_version = game_kwargs["game_version"]
    game.map = game_kwargs["map"]
    game.game_type = game_kwargs["game_type"]
    game.duration = game_kwargs["duration"]
    game.game_duration = game_kwargs["game_duration"]
    game.winner = game_kwargs["winner"]
    game.players = game_kwargs["players"]
    game.event_types = game_kwargs["event_types"]
    game.key_events = game_kwargs["key_events"]
    game.parse_iteration = game_kwargs["parse_iteration"]
    game.is_final = True
    game.disconnect_detected = game_kwargs["disconnect_detected"]
    game.parse_source = game_kwargs["parse_source"]
    game.parse_reason = game_kwargs["parse_reason"]
    game.timestamp = datetime.utcnow()
    if game_kwargs.get("played_on") is not None:
        game.played_on = game_kwargs["played_on"]


def _metadata_player_count_from_game(game):
    players = getattr(game, "players", None)
    if isinstance(players, list):
        return len(
            [
                player
                for player in players
                if isinstance(player, dict) and _clean_metadata_string(player.get("name"), 100)
            ]
        )
    return 0


def _should_refresh_watcher_metadata_final(existing_game, incoming_game_kwargs: dict):
    existing_parse_reason = getattr(existing_game, "parse_reason", None)
    if existing_parse_reason == FINAL_UNPARSED_PARSE_REASON:
        return True
    if existing_parse_reason != FINAL_METADATA_PARSE_REASON:
        return False

    existing_key_events = getattr(existing_game, "key_events", {}) or {}
    incoming_key_events = incoming_game_kwargs.get("key_events") or {}
    existing_count = _metadata_player_count_from_game(existing_game)
    incoming_count = len(incoming_game_kwargs.get("players") or [])
    if incoming_count > existing_count:
        return True

    if (
        incoming_key_events.get("trusted_player_data") is True
        and existing_key_events.get("trusted_player_data") is not True
    ):
        return True

    existing_winner = _clean_metadata_string(getattr(existing_game, "winner", None), 100)
    incoming_winner = _clean_metadata_string(incoming_game_kwargs.get("winner"), 100)
    if incoming_winner and incoming_winner != "Unknown" and existing_winner in {None, "", "Unknown"}:
        return True

    existing_map = getattr(existing_game, "map", {}) or {}
    incoming_map = incoming_game_kwargs.get("map") or {}
    existing_map_name = _clean_metadata_string(existing_map.get("name") if isinstance(existing_map, dict) else None, 120)
    incoming_map_name = _clean_metadata_string(incoming_map.get("name") if isinstance(incoming_map, dict) else None, 120)
    if incoming_map_name and incoming_map_name != "Unknown" and existing_map_name in {None, "", "Unknown"}:
        return True

    return False


async def _store_metadata_final_upload(
    db,
    *,
    uploader_uid: Optional[str],
    replay_hash: str,
    original_name: str,
    parsed: Optional[dict],
    parse_source: str,
    parser_error: Optional[str],
    parse_iteration: int,
    upload_mode: str,
    file_size_bytes: Optional[int],
    normalized_metadata: dict,
):
    game_kwargs = _build_metadata_final_game_kwargs(
        parsed=parsed,
        normalized_metadata=normalized_metadata,
        parse_source=parse_source,
        parser_error=parser_error,
        parse_iteration=parse_iteration,
    )

    existing_final_game = await _load_existing_final_by_replay_hash(db, replay_hash)
    if existing_final_game:
        if _should_refresh_watcher_metadata_final(existing_final_game, game_kwargs):
            _apply_final_game_kwargs(
                existing_final_game,
                uploader_uid=uploader_uid,
                original_name=original_name,
                replay_hash=replay_hash,
                game_kwargs=game_kwargs,
            )
            await _record_parse_attempt(
                db,
                user_uid=uploader_uid,
                replay_hash=replay_hash,
                original_filename=original_name,
                parse_source=game_kwargs["parse_source"],
                status="duplicate_final_metadata_refreshed",
                detail="Replay final refreshed with watcher metadata after parser failure.",
                upload_mode=upload_mode,
                file_size_bytes=file_size_bytes,
                game_stats_id=existing_final_game.id,
                played_on=game_kwargs["played_on"],
            )
            await db.commit()
            return {
                "message": "Final replay refreshed with watcher metadata.",
                "replay_hash": replay_hash,
                "winner": game_kwargs["winner"],
                "players_count": len(game_kwargs["players"]),
                "uploader_uid": uploader_uid,
                "upload_mode": upload_mode,
                "parse_iteration": parse_iteration,
                "is_final": True,
                "metadata_final": True,
                "parse_reason": FINAL_METADATA_PARSE_REASON,
            }

        await _record_parse_attempt(
            db,
            user_uid=uploader_uid,
            replay_hash=replay_hash,
            original_filename=original_name,
            parse_source=game_kwargs["parse_source"],
            status="duplicate_final",
            detail="Replay already stored as final. Skipped.",
            upload_mode=upload_mode,
            file_size_bytes=file_size_bytes,
            game_stats_id=existing_final_game.id,
            played_on=game_kwargs["played_on"],
        )
        await db.commit()
        return {
            "message": "Replay already stored as final. Skipped.",
            "replay_hash": replay_hash,
            "uploader_uid": uploader_uid,
            "upload_mode": upload_mode,
            "is_final": True,
            "metadata_final": existing_final_game.parse_reason == FINAL_METADATA_PARSE_REASON,
            "parse_reason": existing_final_game.parse_reason,
        }

    previous_versions = []
    if original_name and uploader_uid and uploader_uid != "system":
        prior = await db.execute(
            select(GameStats.id, GameStats.replay_hash).where(
                GameStats.user_uid == uploader_uid,
                GameStats.original_filename == original_name,
                GameStats.is_final.is_(True),
            )
        )
        previous_versions = [
            row.id
            for row in prior
            if row.replay_hash != replay_hash
        ]

    game = GameStats(
        user_uid=uploader_uid or "system",
        replay_file=original_name,
        replay_hash=replay_hash,
        original_filename=original_name,
        **game_kwargs,
    )
    db.add(game)
    await db.flush()

    if previous_versions:
        await db.execute(
            update(GameStats)
            .where(GameStats.id.in_(previous_versions))
            .values(
                is_final=False,
                parse_reason=SUPERSEDED_PARSE_REASON,
            )
        )

    await _record_parse_attempt(
        db,
        user_uid=uploader_uid,
        replay_hash=replay_hash,
        original_filename=original_name,
        parse_source=game_kwargs["parse_source"],
        status="stored_final_metadata",
        detail="Final replay stored with watcher metadata because replay parsing failed.",
        upload_mode=upload_mode,
        file_size_bytes=file_size_bytes,
        game_stats_id=game.id,
        played_on=game_kwargs["played_on"],
    )
    await db.commit()
    return {
        "message": "Final replay stored with watcher metadata.",
        "replay_hash": replay_hash,
        "winner": game_kwargs["winner"],
        "players_count": len(game_kwargs["players"]),
        "uploader_uid": uploader_uid,
        "upload_mode": upload_mode,
        "parse_iteration": parse_iteration,
        "is_final": True,
        "pending_parse": False,
        "metadata_final": True,
        "parse_reason": FINAL_METADATA_PARSE_REASON,
    }


def _key_event_chat_count(value):
    if isinstance(value, dict):
        return _coerce_positive_int(value.get("chat_count"))
    return 0


def _key_event_bool(value, key: str) -> bool:
    if isinstance(value, dict):
        return bool(value.get(key))
    return False


def _key_event_score_count(value) -> int:
    if isinstance(value, dict):
        return _coerce_positive_int(value.get("player_score_count"))
    return 0


def _key_event_achievement_count(value) -> int:
    if isinstance(value, dict):
        return _coerce_positive_int(value.get("achievement_player_count"))
    return 0


def _event_type_count(value) -> int:
    if isinstance(value, list):
        return len([entry for entry in value if entry])
    return 0


def _has_trusted_player_data(players: Optional[list], key_events: dict):
    if not isinstance(players, list) or len(players) < 2:
        return False

    if isinstance(key_events, dict) and key_events.get("trusted_player_data") is False:
        return False

    player_source = str(key_events.get("player_extraction_source") or "").strip()
    if player_source in {"", "no_players", "summary_unavailable"}:
        return False

    named_players = [
        player
        for player in players
        if isinstance(player, dict) and str(player.get("name") or "").strip()
    ]
    return len(named_players) >= 2


def _has_replay_trusted_player_data(players: Optional[list], key_events: dict):
    if not _has_trusted_player_data(players, key_events):
        return False
    if isinstance(key_events, dict):
        if key_events.get("replay_parser_trust") is False:
            return False
        if key_events.get("player_data_source") == "watcher_metadata":
            return False
        if key_events.get("bet_arming_eligible") is False:
            return False
    return True


def _should_upgrade_duplicate_final(
    existing_game,
    incoming_parse_reason: Optional[str],
    incoming_disconnect_detected: bool,
    incoming_key_events: dict,
    incoming_players: Optional[list] = None,
):
    existing_key_events = getattr(existing_game, "key_events", {}) or {}
    existing_parse_reason = getattr(existing_game, "parse_reason", None)

    if (
        existing_parse_reason in {FINAL_UNPARSED_PARSE_REASON, FINAL_METADATA_PARSE_REASON}
        and _has_replay_trusted_player_data(incoming_players, incoming_key_events)
    ):
        return True

    if incoming_parse_reason == "recorded_resignation_final" and existing_parse_reason != incoming_parse_reason:
        return True

    incoming_completion_source = (
        incoming_key_events.get("completion_source") if isinstance(incoming_key_events, dict) else None
    )
    existing_completion_source = (
        existing_key_events.get("completion_source") if isinstance(existing_key_events, dict) else None
    )
    if incoming_completion_source and incoming_completion_source != existing_completion_source:
        return True

    if bool(getattr(existing_game, "disconnect_detected", False)) and not incoming_disconnect_detected:
        return True

    if _key_event_bool(incoming_key_events, "postgame_available") and not _key_event_bool(
        existing_key_events, "postgame_available"
    ):
        return True

    if _key_event_bool(incoming_key_events, "has_achievements") and not _key_event_bool(
        existing_key_events, "has_achievements"
    ):
        return True

    if _key_event_score_count(incoming_key_events) > _key_event_score_count(existing_key_events):
        return True

    if _key_event_achievement_count(incoming_key_events) > _key_event_achievement_count(existing_key_events):
        return True

    incoming_shell_count = _coerce_positive_int(incoming_key_events.get("achievement_shell_count"))
    existing_shell_count = _coerce_positive_int(existing_key_events.get("achievement_shell_count"))
    if incoming_shell_count > existing_shell_count:
        return True

    return False


def _should_refresh_reviewed_match(
    existing_game,
    incoming_duration: int,
    incoming_key_events: dict,
    incoming_players: Optional[list] = None,
    incoming_event_types: Optional[list] = None,
):
    existing_key_events = getattr(existing_game, "key_events", {}) or {}
    existing_duration = _coerce_positive_int(getattr(existing_game, "duration", 0))
    incoming_duration = _coerce_positive_int(incoming_duration)
    if _key_event_bool(incoming_key_events, "postgame_available") and not _key_event_bool(
        existing_key_events, "postgame_available"
    ):
        return True
    if _key_event_bool(incoming_key_events, "has_achievements") and not _key_event_bool(
        existing_key_events, "has_achievements"
    ):
        return True
    if _key_event_bool(incoming_key_events, "completed") and not _key_event_bool(
        existing_key_events, "completed"
    ):
        return True
    if _key_event_score_count(incoming_key_events) > _key_event_score_count(existing_key_events):
        return True
    if _key_event_achievement_count(incoming_key_events) > _key_event_achievement_count(existing_key_events):
        return True

    incoming_event_count = _event_type_count(incoming_event_types)
    existing_event_count = _event_type_count(getattr(existing_game, "event_types", []) or [])
    if incoming_event_count >= existing_event_count + 3 and incoming_duration >= existing_duration:
        return True

    if incoming_duration <= existing_duration:
        return False

    if incoming_duration >= existing_duration + 60:
        return True

    existing_chat_count = _key_event_chat_count(existing_key_events)
    incoming_chat_count = _key_event_chat_count(incoming_key_events)
    return incoming_chat_count >= existing_chat_count + 3 and incoming_duration >= existing_duration + 30


async def _maybe_verify_user_from_replay(db, uploader_uid: str, players: list, claimed_name: Optional[str], method: str):
    """
    If user has a claimed in_game_name (or header provided) and it appears in parsed replay player list,
    mark verified + lock name.
    """
    if User is None:
        return
    if not uploader_uid or uploader_uid == "system":
        return
    if not isinstance(players, list) or not players:
        return

    res = await db.execute(select(User).where(User.uid == uploader_uid))
    user = res.scalars().first()
    if not user:
        return

    claim = (claimed_name or user.in_game_name or "").strip()
    if not claim:
        return

    claim_norm = _norm_name(claim)
    matched = None

    for p in players:
        if not isinstance(p, dict):
            continue
        nm = str(p.get("name", "")).strip()
        if nm and _norm_name(nm) == claim_norm:
            matched = nm
            break

    if not matched:
        return

    # If not locked, normalize stored name to replay spelling
    if not getattr(user, "lock_name", False):
        user.in_game_name = matched

    user.verified = True
    user.lock_name = True
    user.verification_level = 2
    user.verification_method = method
    user.verified_at = datetime.utcnow()


@router.post("/parse_replay")
async def parse_new_replay(
    data: ParseReplayRequest,
    db_gen=Depends(get_db),
    _: bool = Depends(require_internal_key),
    user_uid: str = Header(default="system", alias="x-user-uid"),
    mode: str = Query(default=None),
):
    async with db_gen as db:
        raw_duration = data.duration or data.game_duration or 0
        duration = int(raw_duration) if isinstance(raw_duration, (int, float)) else 0
        map_payload = _map_payload(data)
        played_on = _safe_iso_datetime(data.played_on)
        players = data.players
        key_events = data.key_events if isinstance(data.key_events, dict) else {}
        winner = data.winner
        disconnect_detected = bool(data.disconnect_detected)
        parse_reason = data.parse_reason or "json_submission"

        if mode == "final" and data.is_final:
            uploader_user = await _load_user_by_uid(db, user_uid)
            inferred_outcome = _infer_incomplete_uploader_outcome(
                {
                    "winner": winner,
                    "players": players,
                    "completed": key_events.get("completed"),
                    "key_events": key_events,
                    "disconnect_detected": disconnect_detected,
                    "parse_reason": parse_reason,
                },
                uploader_user,
                None,
            )
            if inferred_outcome:
                players = inferred_outcome["players"]
                winner = inferred_outcome["winner"]
                disconnect_detected = inferred_outcome["disconnect_detected"]
                parse_reason = inferred_outcome["parse_reason"]
                key_events = inferred_outcome["key_events"]

            existing = await db.execute(
                select(GameStats).where(
                    GameStats.replay_hash == data.replay_hash,
                    GameStats.is_final.is_(True),
                )
            )
            existing_final_game = existing.scalars().first()
            if existing_final_game:
                parse_source = data.parse_source or "json_parse"
                if _should_upgrade_duplicate_final(
                    existing_final_game,
                    parse_reason,
                    disconnect_detected,
                    key_events,
                    players,
                ):
                    parsed_payload = {
                        "game_version": data.game_version,
                        "game_type": data.game_type,
                    }
                    _apply_parsed_upload_to_game(
                        existing_final_game,
                        uploader_uid=user_uid,
                        replay_hash=data.replay_hash,
                        original_name=data.original_filename or data.replay_file,
                        parsed=parsed_payload,
                        map_payload=map_payload,
                        duration=duration,
                        winner=winner,
                        players=players,
                        event_types=data.event_types,
                        key_events=key_events,
                        parse_iteration=data.parse_iteration,
                        is_final_upload=True,
                        disconnect_detected=disconnect_detected,
                        parse_source=parse_source,
                        parse_reason=parse_reason,
                        played_on=played_on,
                    )

                    await _record_parse_attempt(
                        db,
                        user_uid=user_uid,
                        replay_hash=data.replay_hash,
                        original_filename=data.original_filename,
                        parse_source=parse_source,
                        status="duplicate_final_refreshed",
                        detail="Replay final refreshed with clearer completion metadata.",
                        upload_mode="internal_json",
                        file_size_bytes=None,
                        game_stats_id=existing_final_game.id,
                        played_on=played_on,
                    )
                    await db.commit()
                    return {"message": "Replay final refreshed with clearer completion metadata."}

                logging.info(f"🛡️ Skipped duplicate final replay: {data.replay_hash}")
                return {"message": "Replay already parsed as final. Skipped."}

            platform_match_id = _extract_platform_match_id(data.key_events)
            existing_platform_match = await _load_existing_final_by_platform_match_id(
                db,
                platform_match_id,
            )
            if existing_platform_match and existing_platform_match.replay_hash != data.replay_hash:
                logging.info(
                    "🛡️ Skipped reviewed platform match duplicate: %s (%s)",
                    platform_match_id,
                    data.replay_hash,
                )
                return {"message": "Reviewed match already stored. Skipped."}

        game = GameStats(
            user_uid=user_uid,
            replay_file=data.replay_file,
            replay_hash=data.replay_hash,
            game_version=data.game_version,
            map=map_payload,
            game_type=data.game_type,
            duration=duration,
            game_duration=duration,
            winner=winner,
            players=players,
            event_types=data.event_types,
            key_events=key_events,
            parse_iteration=data.parse_iteration,
            is_final=data.is_final,
            disconnect_detected=disconnect_detected,
            parse_source=data.parse_source or "json_parse",
            parse_reason=parse_reason,
            original_filename=data.original_filename,
            played_on=played_on,
        )
        db.add(game)
        await db.commit()

        return {"message": f"Replay stored (iteration {data.parse_iteration})"}


@router.post("/replay/upload")
async def upload_replay_file(
    file: UploadFile = File(...),
    metadata: Optional[str] = Form(default=None),
    db_gen=Depends(get_db),
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
    user_uid: str = Header(default="system", alias="x-user-uid"),
    x_player_name: Optional[str] = Header(default=None, alias="x-player-name"),
    x_parse_iteration: Optional[str] = Header(default=None, alias="x-parse-iteration"),
    x_is_final: Optional[str] = Header(default=None, alias="x-is-final"),
    x_parse_source: Optional[str] = Header(default=None, alias="x-parse-source"),
    x_parse_reason: Optional[str] = Header(default=None, alias="x-parse-reason"),
):
    original_name = file.filename or "replay.aoe2record"
    suffix = Path(original_name).suffix.lower()
    if suffix not in {".aoe2record", ".aoe2mpgame", ".mgz", ".mgx", ".mgl"}:
        raise HTTPException(status_code=400, detail="Unsupported replay file type")

    fd, temp_path = tempfile.mkstemp(prefix="aoe2-replay-", suffix=suffix)
    os.close(fd)
    written = 0

    try:
        with open(temp_path, "wb") as handle:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_REPLAY_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Replay file too large")
                handle.write(chunk)
    finally:
        await file.close()

    try:
        replay_hash = await hash_replay_file(temp_path)
        if not replay_hash:
            raise HTTPException(status_code=500, detail="Failed to hash replay file")

        parse_failure_detail = (
            "Failed to parse replay file. The replay may still be finalizing on disk; retry shortly."
        )

        async with db_gen as db:
            uploader_uid, mode = await _resolve_upload_identity(db, x_api_key, user_uid)
            uploader_user = await _load_user_by_uid(db, uploader_uid)
            is_final_upload = _parse_bool_header(x_is_final, True)
            parse_iteration = _parse_positive_int_header(x_parse_iteration, 1)
            parse_source_hint, _ = _derive_upload_parse_metadata(
                upload_mode=mode,
                is_final=is_final_upload,
                requested_source=x_parse_source,
                requested_reason=x_parse_reason,
                parsed_reason=None,
            )
            watcher_metadata_raw, watcher_metadata_error = _parse_watcher_metadata(
                metadata,
                replay_hash,
            )
            normalized_watcher_metadata = _normalize_watcher_metadata(
                watcher_metadata_raw,
                replay_hash=replay_hash,
                original_name=original_name,
                uploader_uid=uploader_uid,
                file_size_bytes=written,
            )
            if watcher_metadata_error:
                logging.warning(
                    "⚠️ ignored watcher metadata for %s hash=%s: %s",
                    original_name,
                    replay_hash,
                    watcher_metadata_error,
                )

            parsed, parser_error = await parse_replay_full_with_error(
                temp_path,
                apply_hd_early_exit_rules=is_final_upload,
            )
            if not parsed:
                if not is_final_upload and mode == "watcher":
                    placeholder_key_events = {
                        "completed": False,
                        "live_pending_parse": True,
                    }
                    existing_placeholder_live = await _load_existing_placeholder_live_game(
                        db,
                        uploader_uid,
                        original_name,
                    )

                    if existing_placeholder_live:
                        existing_placeholder_live.user_uid = uploader_uid or existing_placeholder_live.user_uid
                        existing_placeholder_live.replay_file = original_name
                        existing_placeholder_live.replay_hash = replay_hash
                        existing_placeholder_live.parse_iteration = parse_iteration
                        existing_placeholder_live.is_final = False
                        existing_placeholder_live.disconnect_detected = False
                        existing_placeholder_live.parse_source = parse_source_hint
                        existing_placeholder_live.parse_reason = PLACEHOLDER_LIVE_PARSE_REASON
                        existing_placeholder_live.original_filename = original_name
                        existing_placeholder_live.key_events = placeholder_key_events
                        existing_placeholder_live.timestamp = datetime.utcnow()
                    else:
                        existing_placeholder_live = GameStats(
                            user_uid=uploader_uid or "system",
                            replay_file=original_name,
                            replay_hash=replay_hash,
                            game_version=None,
                            map={"name": "Unknown", "size": "Unknown"},
                            game_type=None,
                            duration=0,
                            game_duration=0,
                            winner="Unknown",
                            players=[],
                            event_types=[],
                            key_events=placeholder_key_events,
                            parse_iteration=parse_iteration,
                            is_final=False,
                            disconnect_detected=False,
                            parse_source=parse_source_hint,
                            parse_reason=PLACEHOLDER_LIVE_PARSE_REASON,
                            original_filename=original_name,
                            played_on=None,
                        )
                        db.add(existing_placeholder_live)
                        await db.flush()

                    await _record_parse_attempt(
                        db,
                        user_uid=uploader_uid,
                        replay_hash=replay_hash,
                        original_filename=original_name,
                        parse_source=parse_source_hint,
                        status="live_pending_parse",
                        detail="Replay detected early; stored placeholder live session until parseable.",
                        upload_mode=mode,
                        file_size_bytes=written,
                        game_stats_id=existing_placeholder_live.id,
                    )
                    await db.commit()
                    return {
                        "message": "Replay detected early; placeholder live session stored.",
                        "replay_hash": replay_hash,
                        "uploader_uid": uploader_uid,
                        "upload_mode": mode,
                        "parse_iteration": parse_iteration,
                        "is_final": False,
                        "pending_parse": True,
                    }

                if is_final_upload:
                    logging.warning(
                        "⚠️ final replay parser failed; storing final fallback row: "
                        f"file={original_name} hash={replay_hash} parser_error={parser_error}"
                    )
                    if _has_meaningful_watcher_metadata(normalized_watcher_metadata):
                        return await _store_metadata_final_upload(
                            db,
                            uploader_uid=uploader_uid,
                            replay_hash=replay_hash,
                            original_name=original_name,
                            parsed=None,
                            parse_source=parse_source_hint,
                            parser_error=parser_error or parse_failure_detail,
                            parse_iteration=parse_iteration,
                            upload_mode=mode,
                            file_size_bytes=written,
                            normalized_metadata=normalized_watcher_metadata,
                        )
                    return await _store_unparsed_final_upload(
                        db,
                        uploader_uid=uploader_uid,
                        replay_hash=replay_hash,
                        original_name=original_name,
                        parsed=None,
                        parse_source=parse_source_hint,
                        parser_error=parser_error or parse_failure_detail,
                        parse_iteration=parse_iteration,
                        upload_mode=mode,
                        file_size_bytes=written,
                    )

                await _record_parse_attempt(
                    db,
                    user_uid=uploader_uid,
                    replay_hash=replay_hash,
                    original_filename=original_name,
                    parse_source=parse_source_hint,
                    status="parse_failed",
                    detail=parse_failure_detail,
                    upload_mode=mode,
                    file_size_bytes=written,
                )
                await db.commit()
                raise HTTPException(status_code=422, detail=parse_failure_detail)

            map_info = parsed.get("map")
            map_payload = {
                "name": map_info.get("name", "Unknown") if isinstance(map_info, dict) else "Unknown",
                "size": map_info.get("size", "Unknown") if isinstance(map_info, dict) else "Unknown",
            }
            players = parsed.get("players") if isinstance(parsed.get("players"), list) else []
            event_types = parsed.get("event_types") if isinstance(parsed.get("event_types"), list) else []
            key_events = parsed.get("key_events") if isinstance(parsed.get("key_events"), dict) else {}
            winner = parsed.get("winner") or "Unknown"
            raw_duration = parsed.get("duration") or parsed.get("game_duration") or 0
            duration = int(raw_duration) if isinstance(raw_duration, (int, float)) else 0
            played_on = _safe_iso_datetime(parsed.get("played_on"))
            disconnect_detected = bool(parsed.get("disconnect_detected"))
            parse_source, parse_reason = _derive_upload_parse_metadata(
                upload_mode=mode,
                is_final=is_final_upload,
                requested_source=x_parse_source,
                requested_reason=x_parse_reason,
                parsed_reason=parsed.get("parse_reason"),
            )
            disconnect_detected = _normalize_live_disconnect_detected(
                is_final_upload,
                disconnect_detected,
                key_events,
            )

            inferred_outcome = None
            if is_final_upload:
                inferred_outcome = _infer_incomplete_uploader_outcome(
                    parsed,
                    uploader_user,
                    x_player_name,
                )
            if inferred_outcome:
                players = inferred_outcome["players"]
                winner = inferred_outcome["winner"]
                disconnect_detected = inferred_outcome["disconnect_detected"]
                parse_reason = inferred_outcome["parse_reason"]
                key_events = inferred_outcome["key_events"]

            if is_final_upload and not _has_reliable_final_signal(parsed, inferred_outcome):
                logging.warning(
                    "⚠️ final replay rejected as not ready: "
                    f"winner={winner} completed={parsed.get('completed')} "
                    f"players={len(players)} "
                    f"player_source={key_events.get('player_extraction_source')} "
                    f"player_error={key_events.get('player_extraction_error')} "
                    f"parse_reason={parse_reason}"
                )
                if _has_meaningful_watcher_metadata(normalized_watcher_metadata):
                    return await _store_metadata_final_upload(
                        db,
                        uploader_uid=uploader_uid,
                        replay_hash=replay_hash,
                        original_name=original_name,
                        parsed=parsed,
                        parse_source=parse_source,
                        parser_error=parser_error or parse_failure_detail,
                        parse_iteration=parse_iteration,
                        upload_mode=mode,
                        file_size_bytes=written,
                        normalized_metadata=normalized_watcher_metadata,
                    )
                return await _store_unparsed_final_upload(
                    db,
                    uploader_uid=uploader_uid,
                    replay_hash=replay_hash,
                    original_name=original_name,
                    parsed=parsed,
                    parse_source=parse_source,
                    parser_error=parser_error or parse_failure_detail,
                    parse_iteration=parse_iteration,
                    upload_mode=mode,
                    file_size_bytes=written,
                )

            if not is_final_upload:
                existing_placeholder_live = await _load_existing_placeholder_live_game(
                    db,
                    uploader_uid,
                    original_name,
                )
                if existing_placeholder_live:
                    _apply_parsed_upload_to_game(
                        existing_placeholder_live,
                        uploader_uid=uploader_uid,
                        replay_hash=replay_hash,
                        original_name=original_name,
                        parsed=parsed,
                        map_payload=map_payload,
                        duration=duration,
                        winner=winner,
                        players=players,
                        event_types=event_types,
                        key_events=key_events,
                        parse_iteration=parse_iteration,
                        is_final_upload=False,
                        disconnect_detected=disconnect_detected,
                        parse_source=parse_source,
                        parse_reason=parse_reason,
                        played_on=played_on,
                    )
                    await _record_parse_attempt(
                        db,
                        user_uid=uploader_uid,
                        replay_hash=replay_hash,
                        original_filename=original_name,
                        parse_source=parse_source,
                        status="live_placeholder_refreshed",
                        detail=f"Replay iteration {parse_iteration} parsed and replaced placeholder live session.",
                        upload_mode=mode,
                        file_size_bytes=written,
                        game_stats_id=existing_placeholder_live.id,
                        played_on=played_on,
                    )
                    await db.commit()
                    return {
                        "message": f"Replay iteration {parse_iteration} parsed and replaced placeholder live session.",
                        "replay_hash": replay_hash,
                        "winner": winner,
                        "players_count": len(players),
                        "uploader_uid": uploader_uid,
                        "upload_mode": mode,
                        "parse_iteration": parse_iteration,
                        "is_final": False,
                    }

            existing_final_game = await _load_existing_final_by_replay_hash(db, replay_hash)
            if existing_final_game:
                if is_final_upload and _should_upgrade_duplicate_final(
                    existing_final_game,
                    parse_reason,
                    disconnect_detected,
                    key_events,
                    players,
                ):
                    existing_final_game.user_uid = uploader_uid or existing_final_game.user_uid
                    existing_final_game.replay_file = original_name
                    existing_final_game.game_version = parsed.get("game_version")
                    existing_final_game.map = map_payload
                    existing_final_game.game_type = parsed.get("game_type")
                    existing_final_game.duration = duration
                    existing_final_game.game_duration = duration
                    existing_final_game.winner = winner
                    existing_final_game.players = players
                    existing_final_game.event_types = event_types
                    existing_final_game.key_events = key_events
                    existing_final_game.parse_iteration = parse_iteration
                    existing_final_game.disconnect_detected = disconnect_detected
                    existing_final_game.parse_source = parse_source
                    existing_final_game.parse_reason = parse_reason
                    existing_final_game.original_filename = original_name
                    existing_final_game.timestamp = datetime.utcnow()
                    if played_on is not None:
                        existing_final_game.played_on = played_on

                    await _record_parse_attempt(
                        db,
                        user_uid=uploader_uid,
                        replay_hash=replay_hash,
                        original_filename=original_name,
                        parse_source=parse_source,
                        status="duplicate_final_refreshed",
                        detail="Replay final refreshed with clearer completion metadata.",
                        upload_mode=mode,
                        file_size_bytes=written,
                        game_stats_id=existing_final_game.id,
                        played_on=played_on,
                    )
                    await db.commit()
                    return {
                        "message": "Replay final refreshed with clearer completion metadata.",
                        "replay_hash": replay_hash,
                        "uploader_uid": uploader_uid,
                        "upload_mode": mode,
                        "parse_iteration": parse_iteration,
                        "is_final": True,
                    }

                await _record_parse_attempt(
                    db,
                    user_uid=uploader_uid,
                    replay_hash=replay_hash,
                    original_filename=original_name,
                    parse_source=parse_source,
                    status="duplicate_final",
                    detail="Replay already parsed as final. Skipped.",
                    upload_mode=mode,
                    file_size_bytes=written,
                    game_stats_id=existing_final_game.id,
                    played_on=played_on,
                )
                await db.commit()
                return {
                    "message": "Replay already parsed as final. Skipped.",
                    "replay_hash": replay_hash,
                    "uploader_uid": uploader_uid,
                    "upload_mode": mode,
                }

            platform_match_id = _extract_platform_match_id(key_events)
            if is_final_upload:
                existing_platform_match = await _load_existing_final_by_platform_match_id(
                    db,
                    platform_match_id,
                )
                if existing_platform_match and existing_platform_match.replay_hash != replay_hash:
                    if _should_refresh_reviewed_match(
                        existing_platform_match,
                        duration,
                        key_events,
                        players,
                        event_types,
                    ):
                        existing_platform_match.user_uid = uploader_uid or existing_platform_match.user_uid
                        existing_platform_match.replay_file = original_name
                        existing_platform_match.replay_hash = replay_hash
                        existing_platform_match.game_version = parsed.get("game_version")
                        existing_platform_match.map = map_payload
                        existing_platform_match.game_type = parsed.get("game_type")
                        existing_platform_match.duration = duration
                        existing_platform_match.game_duration = duration
                        existing_platform_match.winner = winner
                        existing_platform_match.players = players
                        existing_platform_match.event_types = event_types
                        existing_platform_match.key_events = key_events
                        existing_platform_match.parse_iteration = parse_iteration
                        existing_platform_match.is_final = True
                        existing_platform_match.disconnect_detected = disconnect_detected
                        existing_platform_match.parse_source = parse_source
                        existing_platform_match.parse_reason = parse_reason
                        existing_platform_match.original_filename = original_name
                        existing_platform_match.timestamp = datetime.utcnow()
                        if played_on is not None:
                            existing_platform_match.played_on = played_on

                        if uploader_uid and uploader_uid != "system":
                            method = "watcher" if mode == "watcher" else "replay_upload"
                            await _maybe_verify_user_from_replay(db, uploader_uid, players, x_player_name, method)

                        await _record_parse_attempt(
                            db,
                            user_uid=uploader_uid,
                            replay_hash=replay_hash,
                            original_filename=original_name,
                            parse_source=parse_source,
                            status="reviewed_match_refreshed",
                            detail="Reviewed match refreshed with later, more complete final replay data.",
                            upload_mode=mode,
                            file_size_bytes=written,
                            game_stats_id=existing_platform_match.id,
                            played_on=played_on,
                        )
                        await db.commit()
                        return {
                            "message": "Reviewed match refreshed with later final replay data.",
                            "replay_hash": replay_hash,
                            "platform_match_id": platform_match_id,
                            "uploader_uid": uploader_uid,
                            "upload_mode": mode,
                            "parse_iteration": parse_iteration,
                            "is_final": True,
                        }

                    await _record_parse_attempt(
                        db,
                        user_uid=uploader_uid,
                        replay_hash=replay_hash,
                        original_filename=original_name,
                        parse_source=parse_source,
                        status="duplicate_reviewed_match",
                        detail="Reviewed match already stored. Skipped.",
                        upload_mode=mode,
                        file_size_bytes=written,
                        game_stats_id=existing_platform_match.id,
                        played_on=played_on,
                    )
                    await db.commit()
                    return {
                        "message": "Reviewed match already stored. Skipped.",
                        "replay_hash": replay_hash,
                        "platform_match_id": platform_match_id,
                        "uploader_uid": uploader_uid,
                        "upload_mode": mode,
                    }

            if not is_final_upload:
                existing_live = await db.execute(
                    select(GameStats).where(
                        GameStats.replay_hash == replay_hash,
                        GameStats.is_final.is_(False),
                    )
                )
                existing_live_game = existing_live.scalars().first()
                if existing_live_game:
                    if _is_placeholder_live_game(existing_live_game):
                        _apply_parsed_upload_to_game(
                            existing_live_game,
                            uploader_uid=uploader_uid,
                            replay_hash=replay_hash,
                            original_name=original_name,
                            parsed=parsed,
                            map_payload=map_payload,
                            duration=duration,
                            winner=winner,
                            players=players,
                            event_types=event_types,
                            key_events=key_events,
                            parse_iteration=parse_iteration,
                            is_final_upload=False,
                            disconnect_detected=disconnect_detected,
                            parse_source=parse_source,
                            parse_reason=parse_reason,
                            played_on=played_on,
                        )
                        await _record_parse_attempt(
                            db,
                            user_uid=uploader_uid,
                            replay_hash=replay_hash,
                            original_filename=original_name,
                            parse_source=parse_source,
                            status="live_placeholder_refreshed",
                            detail=f"Replay iteration {parse_iteration} parsed and replaced placeholder live session.",
                            upload_mode=mode,
                            file_size_bytes=written,
                            game_stats_id=existing_live_game.id,
                            played_on=played_on,
                        )
                        await db.commit()
                        return {
                            "message": f"Replay iteration {parse_iteration} parsed and replaced placeholder live session.",
                            "replay_hash": replay_hash,
                            "winner": winner,
                            "players_count": len(players),
                            "uploader_uid": uploader_uid,
                            "upload_mode": mode,
                            "parse_iteration": parse_iteration,
                            "is_final": False,
                        }

                    await _record_parse_attempt(
                        db,
                        user_uid=uploader_uid,
                        replay_hash=replay_hash,
                        original_filename=original_name,
                        parse_source=parse_source,
                        status="duplicate_live",
                        detail="Replay iteration already stored. Skipped.",
                        upload_mode=mode,
                        file_size_bytes=written,
                        game_stats_id=existing_live_game.id,
                        played_on=played_on,
                    )
                    await db.commit()
                    return {
                        "message": "Replay iteration already stored. Skipped.",
                        "replay_hash": replay_hash,
                        "uploader_uid": uploader_uid,
                        "upload_mode": mode,
                        "parse_iteration": existing_live_game.parse_iteration,
                    }

            previous_versions = []
            if is_final_upload and original_name and uploader_uid and uploader_uid != "system":
                prior = await db.execute(
                    select(GameStats.id, GameStats.replay_hash).where(
                        GameStats.user_uid == uploader_uid,
                        GameStats.original_filename == original_name,
                        GameStats.is_final.is_(True),
                    )
                )
                previous_versions = [
                    row.id
                    for row in prior
                    if row.replay_hash != replay_hash
                ]

            game = GameStats(
                user_uid=uploader_uid or "system",
                replay_file=original_name,
                replay_hash=replay_hash,
                game_version=parsed.get("game_version"),
                map=map_payload,
                game_type=parsed.get("game_type"),
                duration=duration,
                game_duration=duration,
                winner=winner,
                players=players,
                event_types=event_types,
                key_events=key_events,
                parse_iteration=parse_iteration,
                is_final=is_final_upload,
                disconnect_detected=disconnect_detected,
                parse_source=parse_source,
                parse_reason=parse_reason,
                original_filename=original_name,
                played_on=played_on,
            )
            db.add(game)
            await db.flush()

            if is_final_upload and previous_versions:
                await db.execute(
                    update(GameStats)
                    .where(GameStats.id.in_(previous_versions))
                    .values(
                        is_final=False,
                        parse_reason=SUPERSEDED_PARSE_REASON,
                    )
                )

            # Auto-verify when upload is proof-tied (watcher) or trusted (internal + x-user-uid)
            if is_final_upload and uploader_uid and uploader_uid != "system":
                method = "watcher" if mode == "watcher" else "replay_upload"
                await _maybe_verify_user_from_replay(db, uploader_uid, players, x_player_name, method)

            await _record_parse_attempt(
                db,
                user_uid=uploader_uid,
                replay_hash=replay_hash,
                original_filename=original_name,
                parse_source=parse_source,
                status="stored",
                detail="Replay parsed and stored" if is_final_upload else f"Replay iteration {parse_iteration} stored",
                upload_mode=mode,
                file_size_bytes=written,
                game_stats_id=game.id,
                played_on=played_on,
            )
            await db.commit()

        return {
            "message": "Replay parsed and stored" if is_final_upload else f"Replay iteration {parse_iteration} stored",
            "replay_hash": replay_hash,
            "winner": winner,
            "players_count": len(players),
            "uploader_uid": uploader_uid,
            "upload_mode": mode,
            "parse_iteration": parse_iteration,
            "is_final": is_final_upload,
        }
    finally:
        try:
            os.remove(temp_path)
        except FileNotFoundError:
            pass


@router.get("/health")
async def health_check():
    return {"status": "ok"}
