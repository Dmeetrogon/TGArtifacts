import asyncio
import base64
from dataclasses import dataclass
from typing import Optional, Dict, Tuple

DC_INFO: Dict[int, tuple] = {
    1: ("149.154.175.53", 443),
    2: ("149.154.167.51", 443),
    3: ("149.154.175.100", 443),
    4: ("149.154.167.91", 443),
    5: ("91.108.56.130", 443),
}
DEFAULT_API_ID = 2040
DEFAULT_API_HASH = "b18441a1ff607e10a989891a5462e627"


def parse_string_session(session_string: str) -> Tuple[int, bytes]:
    if not session_string.startswith('1'):
        raise ValueError("Invalid StringSession format")

    data_b64 = session_string[1:]
    padding = 4 - len(data_b64) % 4
    if padding != 4:
        data_b64 += '=' * padding

    data = base64.urlsafe_b64decode(data_b64)

    if len(data) < 263:
        raise ValueError(f"Invalid session data length: {len(data)}")

    dc_id = data[0]
    auth_key = data[7:263]

    if len(auth_key) != 256:
        raise ValueError(f"Invalid auth_key length: {len(auth_key)}")

    return dc_id, auth_key


@dataclass
class SessionValidationResult:
    valid: bool
    user_id: Optional[int] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    error: Optional[str] = None

    def __str__(self) -> str:
        if self.valid:
            name = f"{self.first_name or ''} {self.last_name or ''}".strip()
            return f"Valid session: {name} (@{self.username}) [ID: {self.user_id}]"
        return f"Invalid session: {self.error}"


class SessionValidator:
    def __init__(self, api_id: int = DEFAULT_API_ID, api_hash: str = DEFAULT_API_HASH):
        self.api_id = api_id
        self.api_hash = api_hash

    async def validate_async(self, auth_key: bytes, dc_id: int,
                             expected_user_id: Optional[int] = None) -> SessionValidationResult:
        try:
            from telethon import TelegramClient
            from telethon.sessions import MemorySession
            from telethon.crypto import AuthKey
        except ImportError:
            return SessionValidationResult(valid=False, error="Telethon not installed")

        if len(auth_key) != 256:
            return SessionValidationResult(valid=False, error=f"Invalid auth_key length: {len(auth_key)}")

        if dc_id not in DC_INFO:
            return SessionValidationResult(valid=False, error=f"Invalid DC ID: {dc_id}")

        session = MemorySession()
        session.set_dc(dc_id, DC_INFO[dc_id][0], DC_INFO[dc_id][1])
        session.auth_key = AuthKey(auth_key)

        client = TelegramClient(session, self.api_id, self.api_hash)

        try:
            await client.connect()
            if await client.is_user_authorized():
                me = await client.get_me()
                result = SessionValidationResult(
                    valid=True,
                    user_id=me.id,
                    first_name=me.first_name,
                    last_name=me.last_name,
                    username=me.username,
                    phone=me.phone
                )
                if expected_user_id and me.id != expected_user_id:
                    result.error = f"User ID mismatch: expected {expected_user_id}, got {me.id}"
                return result
            else:
                return SessionValidationResult(valid=False, error="Session not authorized")
        except Exception as e:
            return SessionValidationResult(valid=False, error=str(e))
        finally:
            await client.disconnect()

    def validate(self, auth_key: bytes, dc_id: int,
                 expected_user_id: Optional[int] = None) -> SessionValidationResult:
        return asyncio.run(self.validate_async(auth_key, dc_id, expected_user_id))

    def validate_string_session(self, session_string: str) -> SessionValidationResult:
        try:
            dc_id, auth_key = parse_string_session(session_string)
        except ValueError as e:
            return SessionValidationResult(valid=False, error=str(e))
        return self.validate(auth_key, dc_id)
