from setuptools import setup

setup(
    name='authlib-database',
    version='0.3.0',
    packages=['authlib_database', 'authlib_database.oauth2'],
    url='https://github.com/kyzima-spb/authlib-database',
    license='GNU AGPLv3+',
    author='Kirill Vercetti',
    author_email='office@kyzima-spb.com',
    description='Support for third-party databases in the Autlib library.',
    install_requires=[
        'Authlib>=0.12'
    ]
)
