"""UT-027..034: Extension detector tests."""

import pytest

from tgartifacts.utils.extension_detector import detect_media_extension


# Proper magic byte headers that python-magic recognizes
PNG_HEADER = (
    b'\x89PNG\r\n\x1a\n'
    b'\x00\x00\x00\rIHDR'
    b'\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde'
    + b'\x00' * 100
)
MP4_HEADER = b'\x00\x00\x00\x1cftypisom\x00\x00\x02\x00isomiso2' + b'\x00' * 100
WEBP_HEADER = (
    b'RIFF\x24\x00\x00\x00WEBPVP8 '
    b'\x18\x00\x00\x000\x01\x00\x9d\x01\x2a\x01\x00\x01\x00\x01'
    b'@%\xa4\x00\x03p\x00\xfe\xfb\x94\x00\x00'
)
OGG_HEADER = (
    b'OggS\x00\x02' + b'\x00' * 8 + b'\x00' * 4 + b'\x00' * 4 + b'\x00' * 4
    + b'\x01\x1e'
    + b'\x01vorbis\x00\x00\x00\x00\x02\x44\xac\x00\x00'
    + b'\x00' * 100
)


class TestDetectMediaExtension:
    """UT-027..034: Magic byte detection."""

    def test_ut027_jpeg(self):
        """UT-027: JPEG magic FF D8 FF."""
        data = b'\xff\xd8\xff\xe0' + b'\x00' * 100
        ext = detect_media_extension(data)
        assert ext in ('.jpeg', '.jpg')

    def test_ut028_png(self):
        """UT-028: PNG with proper IHDR header."""
        ext = detect_media_extension(PNG_HEADER)
        assert ext == '.png'

    def test_ut029_mp4(self):
        """UT-029: MP4 ftyp box."""
        ext = detect_media_extension(MP4_HEADER)
        assert ext in ('.mp4', '.m4a', '.m4v')

    def test_ut030_webp(self):
        """UT-030: WebP (RIFF + WEBP + VP8)."""
        ext = detect_media_extension(WEBP_HEADER)
        assert ext == '.webp'

    def test_ut031_ogg(self):
        """UT-031: OGG vorbis audio."""
        ext = detect_media_extension(OGG_HEADER)
        assert ext in ('.ogg', '.oga')

    def test_ut032_pdf(self):
        """UT-032: PDF magic %PDF."""
        data = b'%PDF-1.4' + b'\x00' * 100
        ext = detect_media_extension(data)
        assert ext == '.pdf'

    def test_ut033_random_bytes(self):
        """UT-033: Random bytes → some extension."""
        data = bytes(range(256)) * 2
        ext = detect_media_extension(data)
        assert isinstance(ext, str)
        assert ext.startswith('.')

    def test_ut034_empty_data(self):
        """UT-034: Empty/small data → .bin without exception."""
        assert detect_media_extension(b'') == '.bin'
        assert detect_media_extension(b'\x00' * 5) == '.bin'
