import magic
import mimetypes


def detect_media_extension(data: bytes) -> str:
    """Detect file extension using libmagic.

    Args:
        data: File data

    Returns:
        File extension (e.g., '.mp4', '.ogg', '.jpg') or '.bin' if unknown
    """
    if len(data) < 12:
        return '.bin'

    mime = magic.from_buffer(data, mime=True)
    extension = mimetypes.guess_extension(mime)
    if extension == "None" :
        return ".bin"
    return extension

