
from ..models.account import Account
class JSON_Exporter():
    def __init__(self,account_list:list[Account]):
        self.account_list = account_list
        raui