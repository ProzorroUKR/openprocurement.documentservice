import gevent.monkey
gevent.monkey.patch_all()
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey
from openprocurement.documentservice.utils import auth_check, Root, add_logging_context, read_users, request_params, new_request_subscriber
from pkg_resources import iter_entry_points
from pyramid.authentication import BasicAuthAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from pyramid.events import ContextFound, NewRequest
from sentry_sdk.integrations.logging import LoggingIntegration
from sentry_sdk.integrations.pyramid import PyramidIntegration
import os
import sentry_sdk


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    dsn = settings.get("sentry.dsn") or os.environ.get("SENTRY_DSN")
    if dsn:
        sentry_sdk.init(
            dsn=dsn,
            integrations=[
                LoggingIntegration(),
                PyramidIntegration(),
            ],
            send_default_pii=True,
            request_bodies="always",
            environment=settings.get("sentry.environment"),
        )

    read_users(settings['auth.file'])
    config = Configurator(
        settings=settings,
        authentication_policy=BasicAuthAuthenticationPolicy(auth_check, __name__),
        authorization_policy=ACLAuthorizationPolicy(),
        root_factory=Root,
    )
    config.add_request_method(request_params, 'params', reify=True)
    config.add_subscriber(new_request_subscriber, NewRequest)
    config.add_subscriber(add_logging_context, ContextFound)
    config.include('pyramid_exclog')
    config.add_route('status', '/')
    config.add_route('register', '/register')
    config.add_route('upload', '/upload')
    config.add_route('upload_file', '/upload/{doc_id}')
    config.add_route('get', '/get/{doc_id}')
    config.scan(ignore='openprocurement.documentservice.tests')

    signing_key = settings.get('dockey', '')
    signer = SigningKey(signing_key, encoder=HexEncoder) if signing_key else SigningKey.generate()
    config.registry.signer = signer

    verifier = signer.verify_key
    config.registry.dockey = dockey = verifier.encode(encoder=HexEncoder)[:8].decode()
    config.registry.keyring = keyring = config.registry.dockeyring = dockeyring = {dockey: verifier}

    dockeys = settings.get('dockeys', SigningKey.generate().verify_key.encode(encoder=HexEncoder).decode())
    for key in dockeys.split('\0'):
        dockeyring[key[:8]] = VerifyKey(key, encoder=HexEncoder)

    apikeys = settings.get('apikeys', SigningKey.generate().verify_key.encode(encoder=HexEncoder).decode())
    for key in apikeys.split('\0'):
        keyring[key[:8]] = VerifyKey(key, encoder=HexEncoder)

    config.registry.apikey = key[:8]

    config.registry.upload_host = settings.get('upload_host')
    config.registry.get_host = settings.get('get_host')

    # search for storage
    storage = settings.get('storage')
    for entry_point in iter_entry_points('openprocurement.documentservice.plugins', storage):
        plugin = entry_point.load()
        plugin(config)

    return config.make_wsgi_app()
