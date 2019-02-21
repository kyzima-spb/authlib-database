from website.app import create_app


app = create_app({
    'SECRET_KEY': 'secret',
    'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
    'DB': {
        'provider': 'sqlite',
        'filename': 'db.sqlite',
        'create_db': True
    }
})
