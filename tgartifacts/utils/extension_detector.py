import magic
import mimetypes


def detect_media_extension(data: bytes) -> str:
    if len(data) < 12:
        return '.bin'
    mime = magic.from_buffer(data, mime=True)
    extension = mimetypes.guess_extension(mime)
    if extension is None or extension == "None":
        extension = ".bin"
    return extension
