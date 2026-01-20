from dataclasses import dataclass, field
from typing import Dict, Optional
import hashlib


@dataclass
class MTPAuthorization:
    """MTP Authorization data extracted from Telegram Desktop tdata."""

    user_id: int
    dc_id: int
    auth_keys: Dict[int, bytes] = field(default_factory=dict)
    keys_to_destroy: Dict[int, bytes] = field(default_factory=dict)

    def get_auth_key_id(self, dc_id: int) -> Optional[bytes]:
        """Get auth_key_id (lower 64 bits of SHA1(auth_key)) for a DC.

        Args:
            dc_id: Data center ID

        Returns:
            8-byte auth_key_id or None if key not found
        """
        if dc_id not in self.auth_keys:
            return None
        auth_key = self.auth_keys[dc_id]
        sha1_hash = hashlib.sha1(auth_key).digest()
        return sha1_hash[-8:]  # Lower 64 bits

    def get_auth_key_hex(self, dc_id: int) -> Optional[str]:
        """Get auth key as hex string for a DC.

        Args:
            dc_id: Data center ID

        Returns:
            Hex string of auth key or None if not found
        """
        if dc_id not in self.auth_keys:
            return None
        return self.auth_keys[dc_id].hex()

    @classmethod
    def from_dict(cls, data: Dict) -> 'MTPAuthorization':
        """Create MTPAuthorization from parsed dictionary.

        Args:
            data: Dictionary with user_id, dc_id, auth_keys, keys_to_destroy

        Returns:
            MTPAuthorization instance
        """
        return cls(
            user_id=data.get('user_id', 0),
            dc_id=data.get('dc_id', 0),
            auth_keys=data.get('auth_keys', {}),
            keys_to_destroy=data.get('keys_to_destroy', {})
        )

    def to_dict(self) -> Dict:
        """Convert to dictionary with hex-encoded keys.

        Returns:
            Dictionary representation with hex-encoded auth keys
        """
        return {
            'user_id': self.user_id,
            'dc_id': self.dc_id,
            'auth_keys': {
                dc: key.hex() for dc, key in self.auth_keys.items()
            },
            'auth_key_ids': {
                dc: self.get_auth_key_id(dc).hex() for dc in self.auth_keys
            },
            'keys_to_destroy': {
                dc: key.hex() for dc, key in self.keys_to_destroy.items()
            }
        }