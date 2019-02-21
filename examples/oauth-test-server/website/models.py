import time

from authlib_database.oauth2.pony import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin
)
from pony.orm import Database, Required, Optional, Set


db = Database()


class User(db.Entity):
    username = Required(str, 40, unique=True)
    client = Set('OAuth2Client')
    authorizationcode = Set('OAuth2AuthorizationCode')
    token = Set('OAuth2Token')

    def __str__(self):
        return self.username

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return password == 'valid'


class OAuth2Client(OAuth2ClientMixin(db)):
    user = Required('User')


class OAuth2AuthorizationCode(OAuth2AuthorizationCodeMixin(db)):
    user = Required('User')


class OAuth2Token(OAuth2TokenMixin(db)):
    user = Optional('User')

    def is_refresh_token_expired(self):
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at < time.time()
