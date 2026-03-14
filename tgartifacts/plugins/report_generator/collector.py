import hashlib
import struct
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from tgartifacts.parsers.tdata_parser import TDataParser
from tgartifacts.plugins.hash_report.report import generate_report


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
    accounts_info = parser.get_all_accounts_info()

    cache_dir = output_dir / "cache"
    cache_stats = parser.extract_cached_tdef_files(str(cache_dir))

    hash_data = None
    if cache_dir.exists() and any(cache_dir.rglob("*")):
        hash_data = generate_report(cache_dir)

    accounts = _collect_accounts(accounts_info)

    return {
        "metadata": {
            "timestamp": timestamp,
            "tdata_path": str(tdata_path),
            "passcode_provided": passcode is not None,
        },
        "accounts": accounts,
        "cache": cache_stats,
        "hashes": hash_data,
    }
