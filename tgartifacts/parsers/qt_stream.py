import struct
from typing import Optional


class QtDataStreamReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read_uint32(self) -> int:
        if self.offset + 4 > len(self.data):
            raise ValueError(f"Cannot read uint32 at offset {self.offset}")
        value = struct.unpack('>I', self.data[self.offset:self.offset + 4])[0]
        self.offset += 4
        return value

    def read_int32(self) -> int:
        if self.offset + 4 > len(self.data):
            raise ValueError(f"Cannot read int32 at offset {self.offset}")
        value = struct.unpack('>i', self.data[self.offset:self.offset + 4])[0]
        self.offset += 4
        return value

    def read_uint64(self) -> int:
        if self.offset + 8 > len(self.data):
            raise ValueError(f"Cannot read uint64 at offset {self.offset}")
        value = struct.unpack('>Q', self.data[self.offset:self.offset + 8])[0]
        self.offset += 8
        return value

    def read_bytes(self, length: int) -> bytes:
        if self.offset + length > len(self.data):
            raise ValueError(f"Cannot read {length} bytes at offset {self.offset}")
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        return value

    def read_bytearray(self) -> Optional[bytes]:
        length = self.read_uint32()
        if length == 0xFFFFFFFF:
            return None
        if length == 0:
            return b''
        return self.read_bytes(length)

    def read_utf16(self) -> Optional[str]:
        length = self.read_uint32()
        if length == 0xFFFFFFFF:
            return None
        if length == 0:
            return ''
        return self.read_bytes(length).decode('utf-16-be', errors='replace')

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def peek_uint32(self) -> int:
        if self.offset + 4 > len(self.data):
            raise ValueError(f"Cannot peek uint32 at offset {self.offset}")
        return struct.unpack('>I', self.data[self.offset:self.offset + 4])[0]

    def seek(self, offset: int) -> None:
        if offset < 0 or offset > len(self.data):
            raise ValueError(f"Invalid offset {offset}")
        self.offset = offset

    def skip(self, count: int) -> None:
        if self.offset + count > len(self.data):
            raise ValueError(f"Cannot skip {count} bytes at offset {self.offset}")
        self.offset += count
