from  .MTPAuthorization import MTPAuthorization
class Account:
    def __init__(self,mtp_data: MTPAuthorization, files_names:list[str],files_count:int):
        self.mtp_data = mtp_data
        self.files_names = files_names
        if len(files_names) != 0 and len(files_names) != files_count:
            self.files_count = len(files_names)
