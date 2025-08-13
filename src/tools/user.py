from flask_login import UserMixin
import os


class User(UserMixin):
    def __init__(
        self,
        user_id: str,
        username: str,
        password: str,
        host: str,
    ):
        self.id = user_id
        self.username = username
        self.password = password
        self.host = host
        

    def get_id(self):
        return str(self.id)
