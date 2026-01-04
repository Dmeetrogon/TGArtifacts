from .decryptor import get_TDEF_files


def get_cache_files(path_to_tdata, local_key, output_dir):
    """Get cached files from tdata directory.

    Args:
        path_to_tdata: Path to tdata directory
        local_key: Local encryption key
        output_dir: Output directory for decrypted files

    Returns:
        Dictionary with statistics about processed files
    """
    return get_TDEF_files(path_to_tdata, local_key, output_dir)


