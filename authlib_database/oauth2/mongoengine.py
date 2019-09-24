from time import time

from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7009 import RevocationEndpoint
from mongoengine.fields import *

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


class OAuth2ClientMixin(ClientMixin):
    client_id = StringField(required=True, max_length=48)
    client_secret = StringField(max_length=120)
    issued_at = IntField(required=True, default=lambda: int(time()))
    expires_at = IntField(required=True, default=0)

    redirect_uris = ListField(URLField(), required=True, default=[])
    token_endpoint_auth_method = StringField(max_length=48,
                                             default='client_secret_basic',
                                             choices=['none', 'client_secret_post', 'client_secret_basic'])
    grant_types = ListField(StringField(), required=True, default=[])
    response_types = ListField(StringField(), required=True, default=[]) # code token
    scope = StringField(required=True, default='')

    client_name = StringField(max_length=100, null=True)
    client_uri = URLField(null=True)
    logo_uri = URLField(null=True)
    contacts = ListField(StringField(), default=[])
    tos_uri = URLField(null=True)
    policy_uri = URLField(null=True)
    jwks_uri = URLField(null=True)
    # jwks_text = Column(Text) fixme: ??????
    i18n_metadata = StringField(null=True)

    software_id = StringField(max_length=36, null=True)
    software_version = StringField(max_length=48, null=True)

    meta = {
        'indexes': [
            'client_id'
        ]
    }


class OAuth2AuthorizationCodeMixin(AuthorizationCodeMixin):
    code = StringField(required=True, max_length=120, unique=True)
    client_id = StringField(max_length=48)
    redirect_uri = URLField(null=True)
    response_type = StringField(default='')
    scope = StringField(default='')
    auth_time = IntField(required=True, default=time)


class OAuth2TokenMixin(TokenMixin):
    client_id = StringField(max_length=48)
    token_type = StringField(max_length=40)
    access_token = StringField(required=True, max_length=255, unique=True)
    refresh_token = StringField(max_length=255)
    scope = StringField(default='')
    revoked = BooleanField(default=False)
    issued_at = IntField(required=True, default=time)
    expires_in = IntField(required=True, min_value=0, default=0)

    meta = {
        'indexes': [
            'refresh_token'
        ]
    }


def create_query_client_func(client_model):
    def query_client(client_id):
        return client_model.objects(client_id=client_id).first()
    return query_client


def create_save_token_func(token_model):
    def save_token(token, request):
        user_id = request.user.get_user_id() if request.user else None
        tok = token_model(client_id=request.client.client_id,
                          user=user_id,
                          **token)
        tok.save()
    return save_token


def create_query_token_func(token_model):
    def query_token(token, token_type_hint, client):
        q = token_model.objects(client_id=client.client_id, revoked=False)

        if token_type_hint == 'access_token':
            return q.filter(access_token=token).first()

        if token_type_hint == 'refresh_token':
            return q.filter(refresh_token=token).first()

        # without token_type_hint
        return q.filter(access_token=token).first() or q.filter(refresh_token=token).first()
    return query_token


def create_revocation_endpoint(token_model):
    query_token = create_query_token_func(token_model)

    class _RevocationEndpoint(RevocationEndpoint):
        def query_token(self, token, token_type_hint, client):
            return query_token(token, token_type_hint, client)

        def revoke_token(self, token):
            token.revoked = True
            token.save()

    return _RevocationEndpoint


def create_bearer_token_validator(token_model):
    class _BearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return token_model.objects(access_token=token_string).first()

        def request_invalid(self, request):
            return False

        def token_revoked(self, token):
            return token.revoked

    return _BearerTokenValidator
