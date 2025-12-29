"""Qt Data Stream Parser for Telegram Desktop binary format."""
import struct
from typing import Optional


class QtDataStreamReader:
    """Parser for Qt's QDataStream binary format used by Telegram Desktop.

    Qt uses big-endian byte order for serialization.
    Supported types:
    - uint32, int32, uint64: integers
    - QByteArray: length-prefixed byte arrays
    """

    def __init__(self, data: bytes):
        """Initialize reader with binary data.

        Args:
            data: Binary data to parse
        """
        self.data = data



        self.offset = 0

    def read_uint32(self) -> int:
        """Read 32-bit unsigned integer (big-endian).

        Returns:
            Unsigned 32-bit integer

        Raises:
            ValueError: If not enough data available
        """
        if self.offset + 4 > len(self.data):
            raise ValueError(f"Cannot read uint32 at offset {self.offset}: not enough data")

        value = struct.unpack('>I', self.data[self.offset:self.offset + 4])[0]
        self.offset += 4
        return value

    def read_int32(self) -> int:
        """Read 32-bit signed integer (big-endian).

        Returns:
            Signed 32-bit integer

        Raises:
            ValueError: If not enough data available
        """
        if self.offset + 4 > len(self.data):
            raise ValueError(f"Cannot read int32 at offset {self.offset}: not enough data")

        value = struct.unpack('>i', self.data[self.offset:self.offset + 4])[0]
        self.offset += 4
        return value

    def read_uint64(self) -> int:
        """Read 64-bit unsigned integer (big-endian).

        Returns:
            Unsigned 64-bit integer

        Raises:
            ValueError: If not enough data available
        """
        if self.offset + 8 > len(self.data):
            raise ValueError(f"Cannot read uint64 at offset {self.offset}: not enough data")

        value = struct.unpack('>Q', self.data[self.offset:self.offset + 8])[0]
        self.offset += 8
        return value

    def read_bytes(self, length: int) -> bytes:
        """Read raw bytes.

        Args:
            length: Number of bytes to read

        Returns:
            Raw bytes

        Raises:
            ValueError: If not enough data available
        """
        if self.offset + length > len(self.data):
            raise ValueError(f"Cannot read {length} bytes at offset {self.offset}: not enough data")

        value = self.data[self.offset:self.offset + length]
        self.offset += length
        return value

    def read_bytearray(self) -> Optional[bytes]:
        """Read Qt QByteArray (length-prefixed byte array).

        Format:
        - uint32: length (0xFFFFFFFF = null)
        - bytes: data (if length != 0xFFFFFFFF)

        Returns:
            Byte array or None if null

        Raises:
            ValueError: If not enough data available
        """
        length = self.read_uint32()

        # Qt uses 0xFFFFFFFF to represent null QByteArray
        if length == 0xFFFFFFFF:
            return None

        if length == 0:
            return b''

        return self.read_bytes(length)

    def remaining(self) -> int:
        """Get number of bytes remaining.

        Returns:
            Number of bytes left to read
        """
        return len(self.data) - self.offset

    def peek_uint32(self) -> int:
        """Peek at next uint32 without advancing offset.

        Returns:
            Unsigned 32-bit integer

        Raises:
            ValueError: If not enough data available
        """
        if self.offset + 4 > len(self.data):
            raise ValueError(f"Cannot peek uint32 at offset {self.offset}: not enough data")

        return struct.unpack('>I', self.data[self.offset:self.offset + 4])[0]

    def seek(self, offset: int) -> None:
        """Set absolute read position.

        Args:
            offset: New offset position

        Raises:
            ValueError: If offset is out of bounds
        """
        if offset < 0 or offset > len(self.data):
            raise ValueError(f"Invalid offset {offset}: must be between 0 and {len(self.data)}")

        self.offset = offset

    def skip(self, count: int) -> None:
        """Skip bytes forward.

        Args:
            count: Number of bytes to skip

        Raises:
            ValueError: If would skip beyond data bounds
        """
        if self.offset + count > len(self.data):
            raise ValueError(f"Cannot skip {count} bytes at offset {self.offset}: not enough data")

        self.offset += count
