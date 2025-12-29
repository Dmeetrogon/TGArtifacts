from decryptor import decrypt_local_TETF

def get_cache_files(path_to_tdata,local_key,output_dir):
    decrypt_local_TETF(path_to_tdata,local_key,output_dir)
    return {}


