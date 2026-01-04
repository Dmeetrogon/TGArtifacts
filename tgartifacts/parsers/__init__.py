"""Parsers for Telegram Desktop file formats."""

from .tdf_reader import read_tdf
from .qt_stream import QtDataStreamReader
from .tdata_parser import TDataParser

__all__ = [
    'read_tdf',
    'QtDataStreamReader',
    'TDataParser'
]
