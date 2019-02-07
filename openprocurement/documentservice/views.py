from base64 import b64encode
from logging import getLogger
from openprocurement.documentservice.storage import (
    StorageRedirect, HashInvalid, KeyNotFound, NoContent, ContentUploaded, StorageUploadError)
from openprocurement.documentservice.utils import (
    error_handler, context_unpack, validate_md5, RequestFailure, get_data, file_request, signed_request,
    verify_signature)
from pyramid.httpexceptions import HTTPNoContent
from pyramid.view import view_config
from time import time
from urllib import quote

LOGGER = getLogger(__name__)
EXPIRES = 300


@view_config(route_name='status', renderer='string')
def status_view(request):
    return ''


@view_config(route_name='register', renderer='json', request_method='POST', permission='upload')
def register_view(request):
    data = get_data(request)
    if not isinstance(data, dict) or 'hash' not in data:
        raise RequestFailure(404, 'body', 'hash', 'Not Found')
    md5_hash = data['hash']
    validate_md5(md5_hash)
    uuid = request.registry.storage.register(md5_hash)
    LOGGER.info('Registered new document upload {}'.format(uuid),
                extra=context_unpack(request, {'MESSAGE_ID': 'registered_upload'}, {'doc_id': uuid, 'doc_hash': md5_hash}))
    signature = quote(b64encode(request.registry.signer.signature(uuid)))
    upload_url = request.route_url('upload_file', doc_id=uuid, _query={'Signature': signature, 'KeyID': request.registry.dockey}, _host=request.registry.upload_host or request.domain, _port=request.host_port)
    signature = quote(b64encode(request.registry.signer.signature("{}\0{}".format(uuid, md5_hash[4:]))))
    data['url'] = request.route_url('get', doc_id=uuid, _query={'Signature': signature, 'KeyID': request.registry.dockey}, _host=request.registry.get_host or request.domain, _port=request.host_port)
    request.response.status = 201
    request.response.headers['Location'] = upload_url
    return {'data': data, 'upload_url': upload_url}


@view_config(route_name='upload', renderer='json', request_method='POST', permission='upload')
@file_request
def upload_view(request):
    post_file = request.POST['file']
    uuid, md5, content_type, filename = request.registry.storage.upload(post_file)
    LOGGER.info('Uploaded new document {}'.format(uuid),
                extra=context_unpack(request, {'MESSAGE_ID': 'uploaded_new_document'}, {'doc_id': uuid, 'doc_hash': md5}))
    expires = int(time()) + EXPIRES
    signature = quote(b64encode(request.registry.signer.signature("{}\0{}".format(uuid, md5[4:]))))
    url = request.route_url('get', doc_id=uuid, _query={'Signature': signature, 'KeyID': request.registry.dockey}, _host=request.registry.get_host or request.domain, _port=request.host_port)
    signature = quote(b64encode(request.registry.signer.signature("{}\0{}".format(uuid, expires))))
    get_url = request.route_url('get', doc_id=uuid, _query={'Signature': signature, 'Expires': expires, 'KeyID': request.registry.dockey}, _host=request.registry.get_host or request.domain, _port=request.host_port)
    request.response.headers['Location'] = get_url
    return {'data': {'url': url, 'hash': md5, 'format': content_type, 'title': filename}, 'get_url': get_url}


@view_config(route_name='upload_file', renderer='json', request_method='POST', permission='upload')
@file_request
@signed_request(check_expire=False)
def upload_file_view(request, key, signature):
    uuid = request.matchdict['doc_id']
    verify_signature(key, uuid.encode('utf-8'), signature)
    post_file = request.POST['file']
    try:
        uuid, md5, content_type, filename = request.registry.storage.upload(post_file, uuid)
    except KeyNotFound:
        raise RequestFailure(404, 'url', 'doc_id', 'Not Found')
    except ContentUploaded:
        raise RequestFailure(403, 'url', 'doc_id', 'Content already uploaded')
    except HashInvalid:
        raise RequestFailure(403, 'body', 'file', 'Invalid checksum')

    LOGGER.info('Uploaded document {}'.format(uuid),
                extra=context_unpack(request, {'MESSAGE_ID': 'uploaded_document'}, {'doc_hash': md5}))
    expires = int(time()) + EXPIRES
    signature = quote(b64encode(request.registry.signer.signature("{}\0{}".format(uuid, md5[4:]))))
    url = request.route_url('get', doc_id=uuid, _query={'Signature': signature, 'KeyID': request.registry.dockey}, _host=request.registry.get_host or request.domain, _port=request.host_port)
    signature = quote(b64encode(request.registry.signer.signature("{}\0{}".format(uuid, expires))))
    get_url = request.route_url('get', doc_id=uuid, _query={'Signature': signature, 'Expires': expires, 'KeyID': request.registry.dockey}, _host=request.registry.get_host or request.domain, _port=request.host_port)
    return {'data': {'url': url, 'hash': md5, 'format': content_type, 'title': filename}, 'get_url': get_url}


@view_config(route_name='get', renderer='json', request_method='GET')
@signed_request(check_expire=True)
def get_view(request, key, signature, expires=None):
    uuid = request.matchdict['doc_id']
    mess = "{}\0{}".format(uuid, expires) if expires else uuid
    if request.GET.get('Prefix'):
        mess = '{}/{}'.format(request.GET['Prefix'], mess)
        uuid = '{}/{}'.format(request.GET['Prefix'], uuid)
    verify_signature(key, mess, signature)
    try:
        doc = request.registry.storage.get(uuid)
    except KeyNotFound:
        raise RequestFailure(404, 'url', 'doc_id', 'Not Found')
    except NoContent:
        return HTTPNoContent()
    except StorageRedirect as e:
        request.response.status = 302
        request.response.headers['Location'] = e.url
        return e.url
    else:
        request.response.content_type = doc['Content-Type']
        request.response.content_disposition = doc['Content-Disposition']
        request.response.body = doc['Content']
        return request.response


@view_config(context=RequestFailure, renderer='json')
def request_failure(exc, request):
    body = {'location': exc.location, 'name': exc.name, 'description': exc.description}
    return error_handler(request, exc.status, body)


@view_config(context=StorageUploadError, renderer='json')
def storage_upload_error(exc, request):
    LOGGER.error('Storage error: %s', exc.message, extra=context_unpack(request, {'MESSAGE_ID': 'storage_error'}))
    return error_handler(request, 502, {'description': 'Upload failed, please try again later'})
