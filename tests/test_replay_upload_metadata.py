import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.append(str(Path(__file__).resolve().parents[1]))

from routes.replay_routes_async import (
    FINAL_METADATA_PARSE_REASON,
    FINAL_UNPARSED_PARSE_REASON,
    _build_metadata_final_game_kwargs,
    _build_unparsed_final_game_kwargs,
    _derive_upload_parse_metadata,
    _extract_platform_match_id,
    _has_reliable_final_signal,
    _has_replay_trusted_player_data,
    _infer_incomplete_uploader_outcome,
    _normalize_watcher_metadata,
    _parse_watcher_metadata,
    _normalize_live_disconnect_detected,
    _parse_bool_header,
    _parse_positive_int_header,
    _should_refresh_watcher_metadata_final,
    _should_upgrade_duplicate_final,
    _should_refresh_reviewed_match,
)


def test_parse_bool_header_understands_live_and_final_flags():
    assert _parse_bool_header("true", False) is True
    assert _parse_bool_header("final", False) is True
    assert _parse_bool_header("false", True) is False
    assert _parse_bool_header("live", True) is False
    assert _parse_bool_header(None, True) is True


def test_parse_positive_int_header_uses_positive_values_only():
    assert _parse_positive_int_header("3", 1) == 3
    assert _parse_positive_int_header("0", 1) == 1
    assert _parse_positive_int_header("-7", 2) == 2
    assert _parse_positive_int_header("abc", 4) == 4


def test_derive_upload_parse_metadata_prefers_watcher_live_defaults():
    parse_source, parse_reason = _derive_upload_parse_metadata(
        upload_mode="watcher",
        is_final=False,
        requested_source=None,
        requested_reason=None,
        parsed_reason="watcher_or_browser",
    )

    assert parse_source == "watcher_live"
    assert parse_reason == "watcher_live_iteration"


def test_derive_upload_parse_metadata_preserves_parser_reason_when_specific():
    parse_source, parse_reason = _derive_upload_parse_metadata(
        upload_mode="watcher",
        is_final=True,
        requested_source=None,
        requested_reason=None,
        parsed_reason="hd_early_exit_under_60s",
    )

    assert parse_source == "watcher_final"
    assert parse_reason == "hd_early_exit_under_60s"


def test_derive_upload_parse_metadata_overrides_generic_watcher_reason_with_parser_truth():
    parse_source, parse_reason = _derive_upload_parse_metadata(
        upload_mode="watcher",
        is_final=True,
        requested_source="watcher_final",
        requested_reason="watcher_final_submission",
        parsed_reason="recorded_resignation_final",
    )

    assert parse_source == "watcher_final"
    assert parse_reason == "recorded_resignation_final"


def test_extract_platform_match_id_trims_valid_values():
    assert _extract_platform_match_id({"platform_match_id": "  abc-123  "}) == "abc-123"
    assert _extract_platform_match_id({"platform_match_id": ""}) is None
    assert _extract_platform_match_id({"platform_match_id": None}) is None
    assert _extract_platform_match_id([]) is None


def test_infer_incomplete_uploader_outcome_promotes_opponent_for_long_rated_1v1():
    user = SimpleNamespace(
        steam_id="76561198065420384",
        in_game_name="Emaren",
        steam_persona_name="Emaren",
    )
    parsed = {
        "winner": "Unknown",
        "completed": False,
        "players": [
            {"name": "Emaren", "user_id": "76561198065420384", "winner": None},
            {"name": "Sniper", "user_id": "76561198041444664", "winner": None},
        ],
        "key_events": {
            "rated": True,
            "completed": False,
            "platform_match_id": "abc-123",
        },
    }

    inferred = _infer_incomplete_uploader_outcome(parsed, user, None)

    assert inferred is not None
    assert inferred["winner"] == "Sniper"
    assert inferred["disconnect_detected"] is True
    assert inferred["parse_reason"] == "watcher_inferred_opponent_win_on_incomplete_1v1"
    assert inferred["key_events"]["winner_inference"]["uploader_player"] == "Emaren"


def test_infer_incomplete_uploader_outcome_skips_under_60_no_result():
    user = SimpleNamespace(
        steam_id="76561198065420384",
        in_game_name="Emaren",
        steam_persona_name="Emaren",
    )
    parsed = {
        "winner": "Unknown",
        "completed": False,
        "parse_reason": "hd_early_exit_under_60s",
        "players": [
            {"name": "Emaren", "user_id": "76561198065420384", "winner": None},
            {"name": "kaoritec", "user_id": "76561198904976282", "winner": None},
        ],
        "key_events": {
            "rated": True,
            "completed": False,
            "no_rated_result": True,
        },
    }

    assert _infer_incomplete_uploader_outcome(parsed, user, None) is None


def test_has_reliable_final_signal_accepts_completed_replay():
    assert _has_reliable_final_signal(
        {
            "winner": "Unknown",
            "key_events": {
                "completed": True,
                "postgame_available": False,
            },
        }
    )


def test_has_reliable_final_signal_accepts_inferred_disconnect_outcome():
    inferred = {
        "winner": "Sniper",
    }

    assert _has_reliable_final_signal(
        {
            "winner": "Unknown",
            "key_events": {
                "completed": False,
                "postgame_available": False,
            },
        },
        inferred,
    )


def test_has_reliable_final_signal_rejects_paused_unknown_replay():
    assert not _has_reliable_final_signal(
        {
            "winner": "Unknown",
            "key_events": {
                "completed": False,
                "postgame_available": False,
            },
        }
    )


def test_unparsed_final_kwargs_persist_safe_unknown_match():
    fields = _build_unparsed_final_game_kwargs(
        parsed={
            "game_version": "Version.DE",
            "map": {"name": "Arabia", "size": "Tiny"},
            "game_type": "Random Map",
            "duration": 2450,
            "winner": "Emaren",
            "players": [{"name": "Emaren", "winner": True}],
            "event_types": ["resign"],
            "played_on": "2026-04-21T17:59:10",
            "key_events": {
                "completed": True,
                "completion_source": "scoreboard",
                "player_extraction_error": "summary exploded",
                "standard_header_error": "invalid marker",
                "player_extraction_source": "summary",
                "player_count": 1,
            },
        },
        parse_source="watcher_final",
        parser_error=None,
        parse_iteration=7,
    )

    assert fields["parse_reason"] == FINAL_UNPARSED_PARSE_REASON
    assert fields["is_final"] is True
    assert fields["winner"] == "Unknown"
    assert fields["players"] == []
    assert fields["map"] == {"name": "Arabia", "size": "Tiny"}
    assert fields["duration"] == 2450
    assert fields["played_on"] is not None

    key_events = fields["key_events"]
    assert key_events["final_unparsed"] is True
    assert key_events["trusted_player_data"] is False
    assert key_events["player_extraction_source"] == "no_players"
    assert "player_extraction_error: summary exploded" in key_events["player_extraction_error"]
    assert "standard_header_error: invalid marker" in key_events["player_extraction_error"]
    assert key_events["completed"] is False
    assert key_events["postgame_available"] is False
    assert key_events["player_count"] == 0
    assert "completion_source" not in key_events
    assert not _has_reliable_final_signal(
        {"winner": fields["winner"], "key_events": key_events}
    )


def test_unparsed_final_kwargs_use_parser_error_when_parse_returns_none():
    fields = _build_unparsed_final_game_kwargs(
        parsed=None,
        parse_source="watcher_final",
        parser_error="unsupported DE replay header",
        parse_iteration=2,
    )

    assert fields["parse_reason"] == FINAL_UNPARSED_PARSE_REASON
    assert fields["winner"] == "Unknown"
    assert fields["players"] == []
    assert fields["key_events"]["player_extraction_source"] == "no_players"
    assert fields["key_events"]["player_extraction_error"] == "unsupported DE replay header"


def test_parse_watcher_metadata_rejects_hash_mismatch():
    parsed, error = _parse_watcher_metadata(
        json.dumps({"replay_hash": "b" * 64, "session_id": "session-a"}),
        "a" * 64,
    )

    assert parsed is None
    assert "replay_hash did not match" in error


def test_metadata_final_kwargs_keep_watcher_truth_separate_from_parser_truth():
    replay_hash = "a" * 64
    raw_metadata = {
        "schema": "aoe2dewarwagers.watcher_final_metadata.v1",
        "version": 1,
        "replay_hash": replay_hash,
        "session_id": "watcher-session-1",
        "lobby_id": "lobby-7",
        "filename": "MP Replay v101.102.999 @2026.04.22 183000.aoe2record",
        "started_at": "2026-04-22T18:30:00Z",
        "ended_at": "2026-04-22T19:05:30Z",
        "uploaded_at": "2026-04-22T19:06:00Z",
        "player_count": 2,
        "players": [
            {"name": "Emaren", "civ": "Britons", "color": "Blue", "team": 1},
            {"name": "Sniper", "civ": "Franks", "color": "Red", "team": 2},
        ],
        "map": {"name": "Arabia", "size": "Tiny"},
        "mode": "Random Map",
        "rated": True,
        "winner": {"name": "Emaren", "reliable": False},
        "metadata_sources": ["watcher_file_observation", "local_metadata_sidecar"],
        "trust": {
            "trusted_player_data": True,
            "winner": False,
        },
    }
    normalized = _normalize_watcher_metadata(
        raw_metadata,
        replay_hash=replay_hash,
        original_name="replay.aoe2record",
        uploader_uid="user-1",
        file_size_bytes=1234,
    )

    fields = _build_metadata_final_game_kwargs(
        parsed={
            "winner": "Unknown",
            "completed": False,
            "key_events": {
                "player_extraction_source": "no_players",
                "player_extraction_error": "players -> ai_type failed",
            },
        },
        normalized_metadata=normalized,
        parse_source="watcher_final",
        parser_error=None,
        parse_iteration=4,
    )

    assert fields["parse_reason"] == FINAL_METADATA_PARSE_REASON
    assert fields["is_final"] is True
    assert fields["winner"] == "Unknown"
    assert fields["players"] == [
        {
            "name": "Emaren",
            "source": "watcher_metadata",
            "civilization": "Britons",
            "color": "Blue",
            "team": "1",
            "number": 1,
            "winner": None,
        },
        {
            "name": "Sniper",
            "source": "watcher_metadata",
            "civilization": "Franks",
            "color": "Red",
            "team": "2",
            "number": 2,
            "winner": None,
        },
    ]
    assert fields["map"] == {"name": "Arabia", "size": "Tiny"}
    assert fields["duration"] == 2130

    key_events = fields["key_events"]
    assert key_events["player_data_source"] == "watcher_metadata"
    assert key_events["player_extraction_source"] == "watcher_metadata"
    assert key_events["trusted_player_data"] is True
    assert key_events["replay_parser_trust"] is False
    assert key_events["bet_arming_eligible"] is False
    assert key_events["watcher_final_metadata"] is True
    assert key_events["final_unparsed"] is False
    assert key_events["watcher_metadata"]["session_id"] == "watcher-session-1"
    assert key_events["watcher_metadata"]["winner_reliable"] is False
    assert key_events["replay_parser"]["trusted"] is False
    assert "players -> ai_type failed" in key_events["replay_parser"]["player_extraction_error"]
    assert not _has_replay_trusted_player_data(fields["players"], key_events)


def test_metadata_final_uses_reliable_winner_only_when_marked_trusted():
    replay_hash = "c" * 64
    normalized = _normalize_watcher_metadata(
        {
            "replay_hash": replay_hash,
            "players": [{"name": "Emaren"}, {"name": "Sniper"}],
            "winner": {"name": "Sniper", "reliable": True},
            "trust": {"trusted_player_data": True, "winner": True},
        },
        replay_hash=replay_hash,
        original_name="replay.aoe2record",
        uploader_uid="user-1",
        file_size_bytes=1234,
    )

    fields = _build_metadata_final_game_kwargs(
        parsed=None,
        normalized_metadata=normalized,
        parse_source="watcher_final",
        parser_error="mgz unsupported replay",
        parse_iteration=1,
    )

    assert fields["winner"] == "Sniper"
    assert fields["players"][0]["winner"] is False
    assert fields["players"][1]["winner"] is True
    assert fields["key_events"]["bet_arming_eligible"] is False


def test_normalize_live_disconnect_detected_clears_active_live_false_positive():
    assert not _normalize_live_disconnect_detected(
        False,
        True,
        {
            "completed": False,
            "postgame_available": False,
        },
    )


def test_normalize_live_disconnect_detected_preserves_final_disconnect_signal():
    assert _normalize_live_disconnect_detected(
        True,
        True,
        {
            "completed": False,
        },
    )


def test_should_upgrade_duplicate_final_when_resignation_truth_is_clearer():
    existing_game = SimpleNamespace(
        parse_reason="watcher_final_submission",
        disconnect_detected=True,
        key_events={
            "completed": True,
            "postgame_available": False,
            "has_achievements": False,
            "player_score_count": 0,
            "achievement_player_count": 0,
        },
    )

    assert _should_upgrade_duplicate_final(
        existing_game,
        "recorded_resignation_final",
        False,
        {
            "completed": True,
            "completion_source": "resignation",
            "postgame_available": False,
            "has_achievements": False,
            "player_score_count": 0,
            "achievement_player_count": 0,
            "achievement_shell_count": 2,
        },
    )


def test_should_upgrade_unparsed_final_when_trusted_player_data_arrives():
    existing_game = SimpleNamespace(
        parse_reason=FINAL_UNPARSED_PARSE_REASON,
        disconnect_detected=False,
        key_events={
            "final_unparsed": True,
            "trusted_player_data": False,
            "player_extraction_source": "no_players",
            "player_count": 0,
        },
    )

    assert _should_upgrade_duplicate_final(
        existing_game,
        "watcher_final_submission",
        False,
        {
            "completed": False,
            "player_extraction_source": "header_fallback",
            "player_count": 2,
        },
        [
            {"name": "Emaren", "winner": None},
            {"name": "Sniper", "winner": None},
        ],
    )


def test_should_upgrade_unparsed_final_when_watcher_metadata_arrives():
    existing_game = SimpleNamespace(
        parse_reason=FINAL_UNPARSED_PARSE_REASON,
        winner="Unknown",
        players=[],
        disconnect_detected=False,
        key_events={
            "final_unparsed": True,
            "trusted_player_data": False,
            "player_extraction_source": "no_players",
            "player_count": 0,
        },
        map={"name": "Unknown", "size": "Unknown"},
    )

    assert _should_refresh_watcher_metadata_final(
        existing_game,
        {
            "winner": "Unknown",
            "players": [{"name": "Emaren"}, {"name": "Sniper"}],
            "map": {"name": "Arabia", "size": "Tiny"},
            "key_events": {
                "trusted_player_data": True,
                "player_data_source": "watcher_metadata",
            },
        },
    )


def test_should_upgrade_metadata_final_when_replay_trusted_parse_arrives():
    existing_game = SimpleNamespace(
        parse_reason=FINAL_METADATA_PARSE_REASON,
        disconnect_detected=False,
        key_events={
            "watcher_final_metadata": True,
            "trusted_player_data": True,
            "player_data_source": "watcher_metadata",
            "replay_parser_trust": False,
            "bet_arming_eligible": False,
        },
    )

    assert _should_upgrade_duplicate_final(
        existing_game,
        "recorded_resignation_final",
        False,
        {
            "completed": True,
            "completion_source": "resignation",
            "player_extraction_source": "summary",
            "player_count": 2,
        },
        [
            {"name": "Emaren", "winner": True},
            {"name": "Sniper", "winner": False},
        ],
    )


def test_should_not_upgrade_metadata_final_with_more_watcher_metadata_truth():
    existing_game = SimpleNamespace(
        parse_reason=FINAL_METADATA_PARSE_REASON,
        disconnect_detected=False,
        key_events={
            "watcher_final_metadata": True,
            "trusted_player_data": True,
            "player_data_source": "watcher_metadata",
            "replay_parser_trust": False,
            "bet_arming_eligible": False,
        },
    )

    assert not _should_upgrade_duplicate_final(
        existing_game,
        FINAL_METADATA_PARSE_REASON,
        False,
        {
            "trusted_player_data": True,
            "player_data_source": "watcher_metadata",
            "player_extraction_source": "watcher_metadata",
            "replay_parser_trust": False,
            "bet_arming_eligible": False,
        },
        [
            {"name": "Emaren", "winner": None},
            {"name": "Sniper", "winner": None},
        ],
    )


def test_should_not_upgrade_duplicate_final_without_better_truth():
    existing_game = SimpleNamespace(
        parse_reason="recorded_resignation_final",
        disconnect_detected=False,
        key_events={
            "completed": True,
            "completion_source": "resignation",
            "postgame_available": False,
            "has_achievements": False,
            "player_score_count": 0,
            "achievement_player_count": 0,
        },
    )

    assert not _should_upgrade_duplicate_final(
        existing_game,
        "recorded_resignation_final",
        False,
        {
            "completed": True,
            "completion_source": "resignation",
            "postgame_available": False,
            "has_achievements": False,
            "player_score_count": 0,
            "achievement_player_count": 0,
            "achievement_shell_count": 0,
        },
    )


def test_should_upgrade_duplicate_final_when_achievement_shell_count_improves():
    existing_game = SimpleNamespace(
        parse_reason="recorded_resignation_final",
        disconnect_detected=False,
        key_events={
            "completed": True,
            "completion_source": "resignation",
            "postgame_available": False,
            "has_achievements": False,
            "player_score_count": 0,
            "achievement_player_count": 0,
            "achievement_shell_count": 0,
        },
    )

    assert _should_upgrade_duplicate_final(
        existing_game,
        "recorded_resignation_final",
        False,
        {
            "completed": True,
            "completion_source": "resignation",
            "postgame_available": False,
            "has_achievements": False,
            "player_score_count": 0,
            "achievement_player_count": 0,
            "achievement_shell_count": 2,
        },
    )


def test_should_refresh_reviewed_match_when_later_final_is_much_longer():
    existing_game = SimpleNamespace(
        duration=256,
        key_events={"chat_count": 2},
        event_types=["build", "order"],
    )

    assert _should_refresh_reviewed_match(
        existing_game,
        3288,
        {"chat_count": 2},
        [],
        ["build", "order"],
    )


def test_should_not_refresh_reviewed_match_for_small_progress_bump():
    existing_game = SimpleNamespace(
        duration=1200,
        key_events={"chat_count": 6},
        event_types=["build", "order", "move"],
    )

    assert not _should_refresh_reviewed_match(
        existing_game,
        1220,
        {"chat_count": 6},
        [],
        ["build", "order", "move"],
    )


def test_should_refresh_reviewed_match_when_postgame_truth_arrives():
    existing_game = SimpleNamespace(
        duration=61,
        key_events={
            "completed": True,
            "postgame_available": False,
            "has_achievements": False,
            "player_score_count": 0,
            "achievement_player_count": 0,
            "chat_count": 1,
        },
        event_types=["order", "move", "build"],
    )

    assert _should_refresh_reviewed_match(
        existing_game,
        61,
        {
            "completed": True,
            "postgame_available": True,
            "has_achievements": True,
            "player_score_count": 2,
            "achievement_player_count": 2,
            "chat_count": 1,
        },
        [],
        ["order", "move", "build"],
    )


def test_should_refresh_reviewed_match_when_scores_arrive_without_duration_gain():
    existing_game = SimpleNamespace(
        duration=300,
        key_events={
            "completed": True,
            "postgame_available": False,
            "has_achievements": False,
            "player_score_count": 0,
            "achievement_player_count": 0,
            "chat_count": 4,
        },
        event_types=["order", "move"],
    )

    assert _should_refresh_reviewed_match(
        existing_game,
        300,
        {
            "completed": True,
            "postgame_available": False,
            "has_achievements": False,
            "player_score_count": 2,
            "achievement_player_count": 0,
            "chat_count": 4,
        },
        [],
        ["order", "move"],
    )
