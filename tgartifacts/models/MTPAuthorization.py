class MTPAuthorization:
    def __init__(self,user_id:str, phone:str, dc_id:str,auth_keys: tuple[bytes,bytes]):
        self.user_id = user_id
        self.phone = phone
        self.dc_id = dc_id
        self.auth_keys = auth_keys