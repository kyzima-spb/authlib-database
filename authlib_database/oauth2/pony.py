import time

from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7009 import RevocationEndpoint
from pony.orm import *

from . import ClientMixin, AuthorizationCodeMixin, TokenMixin


__all__ = [
    'OAuth2ClientMixin',
    'OAuth2AuthorizationCodeMixin',
    'OAuth2TokenMixin',
    'create_query_client_func',
    'create_save_token_func',
    'create_query_token_func',
    'create_revocation_endpoint',
    'create_bearer_token_validator'
]


def current_timestamp():
    return int(time.time())


def OAuth2ClientMixin(db):
    class OAuth2ClientMixin(db.Entity, ClientMixin):
        _table_ = 'oauth2_client'

        client_id = Optional(str, 48, index=True)
        client_secret = Optional(str, 120)
        issued_at = Required(int, default=current_timestamp)
        expires_at = Required(int, default=0)

        redirect_uris = Required(StrArray, default=[])
        token_endpoint_auth_method = Optional(str, 48, default='client_secret_basic')
        grant_types = Required(StrArray, default=[])
        response_types = Required(StrArray, default=[])
        scope = Optional(LongStr, default='') # Required, but may be empty

        client_name = Optional(str, 100, default='')
        client_uri = Optional(LongStr, default='')
        logo_uri = Optional(LongStr, default='')
        contacts = Optional(StrArray, default=[])
        tos_uri = Optional(LongStr, default='')
        policy_uri = Optional(LongStr, default='')
        jwks_uri = Optional(LongStr, default='')
        jwks_text = Optional(LongStr, default='')
        i18n_metadata = Optional(LongStr, default='')

        software_id = Optional(str, 36, default='')
        software_version = Optional(str, 48, default='')
    return OAuth2ClientMixin


def OAuth2AuthorizationCodeMixin(db):
    class OAuth2AuthorizationCodeMixin(db.Entity, AuthorizationCodeMixin):
        _table_ = 'oauth2_authorization_code'

        code = Required(str, 120, unique=True)
        client_id = Optional(str, 48)
        redirect_uri = Optional(LongStr, default='')
        response_type = Optional(LongStr, default='')
        scope = Optional(LongStr, default='')
        auth_time = Required(int, default=current_timestamp)
    return OAuth2AuthorizationCodeMixin


def OAuth2TokenMixin(db):
    class OAuth2TokenMixin(db.Entity, TokenMixin):
        _table_ = 'oauth2_token'

        client_id = Optional(str, 48)
        token_type = Optional(str, 40)
        access_token = Required(str, 255, unique=True)
        refresh_token = Optional(str, 255, index=True)
        scope = Optional(LongStr, default='')
        revoked = Optional(bool, default=False)
        issued_at = Required(int, default=current_timestamp)
        expires_in = Required(int, default=0)
    return OAuth2TokenMixin


def create_query_client_func(client_model):
    """Create an ``query_client`` function that can be used in authorization server.

    Arguments:
        token_model: Token model class.
    """
    def query_client(client_id):
        return client_model.get(client_id=client_id)
    return query_client


def create_save_token_func(token_model):
    """Create an ``save_token`` function that can be used in authorization server.

    Arguments:
        token_model: Token model class.
    """
    def save_token(token, request):
        user_id = request.user.get_user_id() if request.user else None
        # fixme: здесь точно отвалится
        token_model(client_id=request.client.client_id,
                    user=user_id,
                    **token)
    return save_token


def create_query_token_func(token_model):
    """Create an ``query_token`` function for revocation, introspection token endpoints.

    Arguments:
        token_model: Token model class.
    """
    def query_token(token, token_type_hint, client):
        q = token_model.select(client_id=client.client_id, revoked=False)

        if token_type_hint == 'access_token':
            return q.filter(access_token=token).first()

        if token_type_hint == 'refresh_token':
            return q.filter(refresh_token=token).first()

        # without token_type_hint
        return q.filter(access_token=token).first() or q.filter(refresh_token=token).first()
    return query_token


def create_revocation_endpoint(token_model):
    """Create a revocation endpoint class with SQLAlchemy session and token model.

    Arguments:
        token_model: Token model class.
    """
    query_token = create_query_token_func(token_model)

    class _RevocationEndpoint(RevocationEndpoint):
        def query_token(self, token, token_type_hint, client):
            return query_token(token, token_type_hint, client)

        def revoke_token(self, token):
            token.revoked = True

    return _RevocationEndpoint


def create_bearer_token_validator(token_model):
    """Create an bearer token validator class with SQLAlchemy session and token model.

    Arguments:
        token_model: Token model class.
    """
    class _BearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return token_model.get(access_token=token_string)

        def request_invalid(self, request):
            return False

        def token_revoked(self, token):
            return token.revoked

    return _BearerTokenValidator
