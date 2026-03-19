import hashlib
import struct
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from tgartifacts.parsers.tdata_parser import TDataParser
from tgartifacts.plugins.hash_report.report import generate_report
from tgartifacts.plugins.timeline.analyzer import TimelineAnalyzer


def _compute_auth_key_id(auth_key: bytes) -> str:
    return hashlib.sha1(auth_key).digest()[-8:].hex()


def _create_telethon_string_session(dc_id: int, auth_key: bytes) -> str:
    session_data = struct.pack('>B4sH256s', dc_id, b'\x00\x00\x00\x00', 443, auth_key)
    return '1' + base64.urlsafe_b64encode(session_data).decode('ascii')


def _validate_session(auth_key: bytes, dc_id: int, user_id: Optional[int] = None) -> Dict[str, Any]:
    try:
        from tgartifacts.utils.session_validator import SessionValidator
        validator = SessionValidator()
        result = validator.validate(auth_key, dc_id, expected_user_id=user_id)
        return {
            "status": "valid" if result.valid else "invalid",
            "user_id": result.user_id,
            "first_name": result.first_name,
            "last_name": result.last_name,
            "username": result.username,
            "phone": result.phone,
            "error": result.error,
        }
    except ImportError:
        return {"status": "skipped", "reason": "telethon not installed"}
    except Exception as e:
        return {"status": "skipped", "reason": str(e)}


def _collect_accounts(accounts_info: List[Dict]) -> List[Dict[str, Any]]:
    accounts = []
    for info_data in accounts_info:
        account = {
            "account_dir": info_data.get("account_dir"),
            "success": info_data.get("success", False),
            "error": info_data.get("error"),
        }
        if not info_data.get("success"):
            accounts.append(account)
            continue

        auth_keys = info_data.get("auth_keys", {})
        dc_id = info_data.get("dc_id")

        account.update({
            "user_id": info_data.get("user_id"),
            "dc_id": dc_id,
            "has_passcode": info_data.get("has_passcode", False),
            "auth_key_ids": {
                str(dc): _compute_auth_key_id(key)
                for dc, key in auth_keys.items()
            },
            "sessions": [],
            "validation": None,
        })

        if dc_id and dc_id in auth_keys:
            session_str = _create_telethon_string_session(dc_id, auth_keys[dc_id])
            account["sessions"].append({
                "dc_id": dc_id,
                "string_session": session_str,
            })
            account["validation"] = _validate_session(
                auth_keys[dc_id], dc_id, info_data.get("user_id")
            )

        accounts.append(account)
    return accounts


def collect_report_data(tdata_path: Path, passcode: Optional[str], output_dir: Path) -> Dict[str, Any]:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    parser = TDataParser(str(tdata_path), passcode)

    try:
        settings = parser.get_settings_info()
    except Exception:
        settings = {}

    accounts_info = parser.get_all_accounts_info()

    cache_dir = output_dir / "cache"
    cache_stats = parser.extract_cached_tdef_files(str(cache_dir))

    hash_data = None
    if cache_dir.exists() and any(cache_dir.rglob("*")):
        hash_data = generate_report(cache_dir)

    accounts = _collect_accounts(accounts_info)

    timeline_analyzer = TimelineAnalyzer(tdata_path, accounts_info)
    timeline_report = timeline_analyzer.analyze()
    timeline_data = {
        "total_files": timeline_report.total_files,
        "earliest": str(timeline_report.earliest) if timeline_report.earliest else None,
        "latest": str(timeline_report.latest) if timeline_report.latest else None,
        "anomalies": [
            {
                "severity": a.severity,
                "title": a.title,
                "detail": a.detail,
                "mitre_id": a.mitre_id,
                "events_count": len(a.events),
            }
            for a in timeline_report.anomalies
        ],
        "recent_activity": [
            {"timestamp": str(e.timestamp), "path": e.path}
            for e in timeline_report.events[-20:]
        ],
    }

    settings_data = {}
    if settings:
        settings_data = {
            "tdesktop_version": parser.tdesktop_version,
            "auto_start": settings.get("auto_start"),
            "start_minimized": settings.get("start_minimized"),
            "send_to_menu": settings.get("send_to_menu"),
            "auto_update": settings.get("auto_update"),
            "last_update_check": settings.get("last_update_check"),
            "scale_percent": settings.get("scale_percent"),
            "auto_lock": settings.get("auto_lock"),
            "power_saving": settings.get("power_saving"),
            "phone_number": settings.get("phone_number"),
            "download_path": settings.get("download_path"),
            "dialog_last_path": settings.get("dialog_last_path"),
            "lang_pack_key": settings.get("lang_pack_key"),
            "send_key": settings.get("send_key"),
            "theme": settings.get("theme"),
            "background": settings.get("background"),
            "window_position": settings.get("window_position"),
            "connection": settings.get("connection"),
        }
        config = settings.get("production_config")
        if config:
            dc_opts = config.get("dc_options", [])
            settings_data["production_config"] = {
                "dc_count": len({opt["dc_id"] for opt in dc_opts}),
                "dc_options_total": len(dc_opts),
                "chat_size_max": config.get("chat_size_max"),
                "megagroup_size_max": config.get("megagroup_size_max"),
                "forwarded_count_max": config.get("forwarded_count_max"),
                "edit_time_limit": config.get("edit_time_limit"),
                "revoke_time_limit": config.get("revoke_time_limit"),
            }

    return {
        "metadata": {
            "timestamp": timestamp,
            "tdata_path": str(tdata_path),
            "passcode_provided": passcode is not None,
        },
        "settings": settings_data,
        "accounts": accounts,
        "cache": cache_stats,
        "hashes": hash_data,
        "timeline": timeline_data,
    }
