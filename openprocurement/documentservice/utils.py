import os

from six.moves.configparser import ConfigParser
from base64 import b64decode, b64encode
from datetime import datetime
from time import time
from six.moves.urllib.parse import unquote, quote
from six import b, text_type
from hashlib import sha512
from json import dumps
from logging import getLogger
from nacl.exceptions import BadSignatureError
from pyramid.security import Allow
from pyramid.httpexceptions import exception_response
from pytz import timezone
from webob.multidict import NestedMultiDict
from pythonjsonlogger import jsonlogger

LOGGER = getLogger(__name__)
TZ = timezone(os.environ['TZ'] if 'TZ' in os.environ else 'Europe/Kiev')
USERS = {}
JOURNAL_PREFIX = os.environ.get('JOURNAL_PREFIX', 'JOURNAL_')


def auth_check(username, password, request):
    if username in USERS and USERS[username]['password'] == sha512(b(password)).hexdigest():
        return ['g:{}'.format(USERS[username]['group'])]


class Root(object):
    def __init__(self, request):
        pass

    __acl__ = [
        (Allow, 'g:uploaders', 'upload'),
        (Allow, 'g:api', 'upload'),
    ]


def read_users(filename):
    config = ConfigParser()
    config.read(filename)
    for i in config.sections():
        USERS.update(dict([
            (
                j,
                {
                    'password': k,
                    'group': i
                }
            )
            for j, k in config.items(i)
        ]))


def request_params(request):
    try:
        params = NestedMultiDict(request.GET, request.POST)
    except UnicodeDecodeError:
        response = exception_response(422)
        response.body = dumps(error_handler(request, response.code, {"location": "body", "name": "data", "description": "could not decode params"}))
        response.content_type = 'application/json'
        raise response
    except Exception as e:
        response = exception_response(422)
        response.body = dumps(error_handler(request, response.code, {"location": "body", "name": str(e.__class__.__name__), "description": str(e)}))
        response.content_type = 'application/json'
        raise response
    return params


def add_logging_context(event):
    request = event.request
    request.logging_context = params = {
        'API_KEY': request.registry.apikey,
        'CLIENT_REQUEST_ID': request.headers.get('X-Client-Request-ID', ''),
        'CURRENT_PATH': request.path_info,
        'CURRENT_URL': request.url,
        'DOC_KEY': request.registry.dockey,
        'REMOTE_ADDR': request.remote_addr or '',
        'REQUEST_ID': request.environ.get('REQUEST_ID', ''),
        'REQUEST_METHOD': request.method,
        'TAGS': 'python,docs',
        'USER': str(request.authenticated_userid or ''),
        'USER_AGENT': request.user_agent or '',
    }
    if request.params:
        params['PARAMS'] = str(dict(request.params))
    if request.matchdict:
        for i, j in request.matchdict.items():
            params[i.upper()] = j


def update_logging_context(request, params):
    for x, j in params.items():
        request.logging_context[x.upper()] = j


def context_unpack(request, msg, params=None):
    if params:
        update_logging_context(request, params)
    logging_context = request.logging_context
    journal_context = msg
    for key, value in logging_context.items():
        journal_context[JOURNAL_PREFIX + key] = value
    journal_context[JOURNAL_PREFIX + 'TIMESTAMP'] = datetime.now(TZ).isoformat()
    return journal_context


def error_handler(request, status, error):
    params = {
        'ERROR_STATUS': status
    }
    for key, value in error.items():
        params['ERROR_{}'.format(key)] = value
    LOGGER.info('Error on processing request "{}"'.format(dumps(error)),
                extra=context_unpack(request, {'MESSAGE_ID': 'error_handler'}, params))
    request.response.status = status
    return {
        "status": "error",
        "errors": [error]
    }


def close_open_files(request):
    """Close open temp files"""
    if hasattr(request, 'POST'):
        for field in request.POST.values():
            if hasattr(field, 'file') and field.file and not field.file.closed:
                field.file.close()
    if hasattr(request.body_file_raw, 'closed') and not request.body_file_raw.closed:
        request.body_file_raw.close()


def new_request_subscriber(event):
    request = event.request
    request.add_finished_callback(close_open_files)


class RequestFailure(Exception):
    def __init__(self, status, location, name, description):
        self.status = status
        self.location = location
        self.name = name
        self.description = description


def validate_md5(md5_hash):
    if not md5_hash.startswith('md5:'):
        raise RequestFailure(422, "body", "hash", [u'Hash type is not supported.'])
    if len(md5_hash) != 36:
        raise RequestFailure(422, "body", "hash", [u'Hash value is wrong length.'])
    if set(md5_hash[4:]).difference('0123456789abcdef'):
        raise RequestFailure(422, "body", "hash", [u'Hash value is not hexadecimal.'])


def get_data(request):
    try:
        json = request.json_body
    except ValueError:
        data = request.POST.mixed()
    else:
        data = json.get('data', {})
    return data


def sign_data(signer, msg):
    sign = signer.sign(b(msg)).signature
    return quote(b64encode(sign))


def verify_signature(key, mess, signature):
    try:
        if isinstance(mess, text_type):
            mess = mess.encode('utf-8')
        key.verify(mess, signature)
    except BadSignatureError:
        raise RequestFailure(403, 'url', 'Signature', 'Signature does not match')


def get_host(request):
    return request.registry.get_host or request.domain


def upload_host(request):
    return request.registry.upload_host or request.domain


def generate_route(request, name, uuid, host_func, params):
    query = {'KeyID': request.registry.dockey}
    query.update(params)
    return request.route_url(name, doc_id=uuid, _query=query, _port=request.host_port, _host=host_func(request))


# Request decorators
def file_request(view_callable):
    def inner(request):
        if 'file' not in request.POST or not hasattr(request.POST['file'], 'filename'):
            raise RequestFailure(404, 'body', 'file', 'Not Found')
        return view_callable(request)
    return inner


def signed_request(check_expire):
    def decorator(view_callable):
        def inner(request):
            kwargs = {}
            keyid = request.GET.get('KeyID', request.registry.dockey)
            if check_expire:
                now = int(time())
                expires = request.GET.get('Expires')
                if expires:
                    if expires.isdigit() and int(expires) < now:
                        raise RequestFailure(403, 'url', 'Expires', 'Request has expired')
                    else:
                        kwargs['expires'] = int(expires)
                if keyid not in (request.registry.apikey, request.registry.dockey) and not expires:
                    raise RequestFailure(403, 'url', 'KeyID', 'Key Id does permit to get private document')
                if keyid not in request.registry.keyring:
                    raise RequestFailure(403, 'url', 'KeyID', 'Key Id does not exist')
                key = request.registry.keyring.get(keyid)

            else:
                if keyid not in request.registry.dockeyring:
                    raise RequestFailure(403, 'url', 'KeyID', 'Key Id does not exist')
                key = request.registry.dockeyring.get(keyid)

            if 'Signature' not in request.GET:
                raise RequestFailure(403, 'url', 'Signature', 'Not Found')
            signature = request.GET['Signature']
            try:
                signature = b64decode(unquote(signature))
            except (TypeError, ValueError):
                raise RequestFailure(403, 'url', 'Signature', 'Signature invalid')
            return view_callable(request, key, signature, **kwargs)
        return inner
    return decorator


class FullJsonFormatter(jsonlogger.JsonFormatter):
    def __init__(self, *args, **kwargs):
        kwargs['reserved_attrs'] = []
        super(FullJsonFormatter, self).__init__(*args, **kwargs)
