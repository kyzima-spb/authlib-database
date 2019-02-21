from authlib.common.security import generate_token
from authlib.flask.oauth2 import AuthorizationServer, ResourceProtector
from authlib_database.oauth2.pony import (
    create_query_client_func,
    create_save_token_func,
    create_revocation_endpoint,
    create_bearer_token_validator,
)
from authlib.specs.rfc6749 import grants
from .models import db, User
from .models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    def create_authorization_code(self, client, user, request):
        code = generate_token(48)

        OAuth2AuthorizationCode(code=code,
                                client_id=client.client_id,
                                redirect_uri=request.redirect_uri,
                                scope=request.scope,
                                user_id=user.id)

        return code

    def parse_authorization_code(self, code, client):
        item = db.OAuth2AuthorizationCode.get(code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        authorization_code.delete()
        # code = OAuth2AuthorizationCode.select(lambda o: o.id == authorization_code.id).get()
        # code.delete()

    def authenticate_user(self, authorization_code):
        return authorization_code.user
        # return db.User.select(lambda o: o.authorization_code == authorization_code).get()


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):
        user = User.get(username=username)
        if user and user.check_password(password):
            return user


class RefreshTokenGrant(grants.RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        item = OAuth2Token.get(refresh_token=refresh_token)
        if item and not item.is_refresh_token_expired():
            return item

    def authenticate_user(self, credential):
        return User[credential.user.id]


query_client = create_query_client_func(OAuth2Client)
save_token = create_save_token_func(OAuth2Token)
authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)
require_oauth = ResourceProtector()


def config_oauth(app):
    authorization.init_app(app)

    # support all grants
    authorization.register_grant(grants.ImplicitGrant)
    authorization.register_grant(grants.ClientCredentialsGrant)
    authorization.register_grant(AuthorizationCodeGrant)
    authorization.register_grant(PasswordGrant)
    authorization.register_grant(RefreshTokenGrant)

    # support revocation
    revocation_cls = create_revocation_endpoint(OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
