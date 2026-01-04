"""Cryptography module for Telegram Desktop file decryption."""

from .decryptor import Decryptor
from .keys import (
    get_key_datas_version,
    create_local_key,
    get_local_key_from_key_datas
)

__all__ = [
    'Decryptor',
    'get_key_datas_version',
    'create_local_key',
    'get_local_key_from_key_datas'
]