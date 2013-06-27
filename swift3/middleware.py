# Copyright (c) 2010 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
The swift3 middleware will emulate the S3 REST api on top of swift.

The following opperations are currently supported:

    * GET Service
    * DELETE Bucket
    * GET Bucket (List Objects)
    * PUT Bucket
    * DELETE Object
    * Delete Multiple Objects
    * GET Object
    * HEAD Object
    * PUT Object
    * PUT Object (Copy)

To add this middleware to your configuration, add the swift3 middleware
in front of the auth middleware, and before any other middleware that
look at swift requests (like rate limiting).

To set up your client, the access key will be the concatenation of the
account and user strings that should look like test:tester, and the
secret access key is the account password.  The host should also point
to the swift storage hostname.  It also will have to use the old style
calling format, and not the hostname based container format.

An example client using the python boto library might look like the
following for an SAIO setup::

    from boto.s3.connection import S3Connection
    connection = S3Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())
"""

from urllib import unquote, quote
import base64
from xml.sax.saxutils import escape as xml_escape
import urlparse
from xml.dom.minidom import parseString
from time import mktime
from dateutil.parser import parse

from simplejson import loads
import email.utils
import datetime
import re

from swift.common.utils import split_path
from swift.common.utils import get_logger
from swift.common.wsgi import WSGIContext
from swift.common.swob import Request, Response
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, \
    HTTP_NOT_FOUND, HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success, \
    HTTP_NOT_IMPLEMENTED, HTTP_LENGTH_REQUIRED, HTTP_SERVICE_UNAVAILABLE


MAX_BUCKET_LISTING = 1000

def to_str(string):
    """Encode if needed with utf8 into str"""
    if isinstance(string, unicode):
        return string.encode('utf8')
    return string

def to_timestamp(last_modified):
    """
    Returns seconds of a datetime since epoch

    :param last_modified: either string in iso format or datetime object
    :returns: string with 6 decimals and 9 integers
    """
    if isinstance(last_modified, basestring):
        last_modified = parse(last_modified)
    sec = mktime(last_modified.timetuple()) + last_modified.microsecond / 1e6
    return "%.6f" % sec

def get_err_response(code):
    """
    Given an HTTP response code, create a properly formatted xml error response

    :param code: error code
    :returns: swift.common.swob.Response object
    """
    error_table = {
        'AccessDenied':
        (HTTP_FORBIDDEN, 'Access denied'),
        'BucketAlreadyExists':
        (HTTP_CONFLICT, 'The requested bucket name is not available'),
        'BucketNotEmpty':
        (HTTP_CONFLICT, 'The bucket you tried to delete is not empty'),
        'InvalidArgument':
        (HTTP_BAD_REQUEST, 'Invalid Argument'),
        'InvalidBucketName':
        (HTTP_BAD_REQUEST, 'The specified bucket is not valid'),
        'InvalidURI':
        (HTTP_BAD_REQUEST, 'Could not parse the specified URI'),
        'InvalidDigest':
        (HTTP_BAD_REQUEST, 'The Content-MD5 you specified was invalid'),
        'BadDigest':
        (HTTP_BAD_REQUEST, 'The Content-Length you specified was invalid'),
        'NoSuchBucket':
        (HTTP_NOT_FOUND, 'The specified bucket does not exist'),
        'SignatureDoesNotMatch':
        (HTTP_FORBIDDEN, 'The calculated request signature does not '
            'match your provided one'),
        'RequestTimeTooSkewed':
        (HTTP_FORBIDDEN, 'The difference between the request time and the'
        ' current time is too large'),
        'NoSuchKey':
        (HTTP_NOT_FOUND, 'The resource you requested does not exist'),
        'Unsupported':
        (HTTP_NOT_IMPLEMENTED, 'The feature you requested is not yet'
        ' implemented'),
        'MissingContentLength':
        (HTTP_LENGTH_REQUIRED, 'Length Required'),
        'ServiceUnavailable':
        (HTTP_SERVICE_UNAVAILABLE, 'Please reduce your request rate')}

    resp = Response(content_type='text/xml')
    resp.status = error_table[code][0]
    resp.body = '<?xml version="1.0" encoding="UTF-8"?>\r\n<Error>\r\n  ' \
                '<Code>%s</Code>\r\n  <Message>%s</Message>\r\n</Error>\r\n' \
                % (code, error_table[code][1])
    return resp


def get_acl(account_name, headers):
    """
    Attempts to construct an S3 ACL based on what is found in the swift headers
    """

    acl = 'private'  # default to private

    if 'x-container-read' in headers:
        if headers['x-container-read'] == ".r:*" or\
            ".r:*," in headers['x-container-read'] or \
                ",*," in headers['x-container-read']:
            acl = 'public-read'
    if 'x-container-write' in headers:
        if headers['x-container-write'] == ".r:*" or\
            ".r:*," in headers['x-container-write'] or \
                ",*," in headers['x-container-write']:
            if acl == 'public-read':
                acl = 'public-read-write'
            else:
                acl = 'public-write'

    if acl == 'private':
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    elif acl == 'public-read':
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="Group">'
                '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                '</Grantee>'
                '<Permission>READ</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    elif acl == 'public-read-write':
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="Group">'
                '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                '</Grantee>'
                '<Permission>READ</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="Group">'
                '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                '</Grantee>'
                '<Permission>WRITE</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    else:
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    return Response(body=body, content_type="text/plain")


def canonical_string(req):
    """
    Canonicalize a request to a token that can be signed.
    """
    amz_headers = {}

    buf = "%s\n%s\n%s\n" % (req.method, req.headers.get('Content-MD5', ''),
                            req.headers.get('Content-Type') or '')

    for amz_header in sorted((key.lower() for key in req.headers
                              if key.lower().startswith('x-amz-'))):
        amz_headers[amz_header] = req.headers[amz_header]

    if 'x-amz-date' in amz_headers:
        buf += "\n"
    elif 'Date' in req.headers:
        buf += "%s\n" % req.headers['Date']

    for k in sorted(key.lower() for key in amz_headers):
        buf += "%s:%s\n" % (k, amz_headers[k])

    # RAW_PATH_INFO is enabled in later version than eventlet 0.9.17.
    # When using older version, swift3 uses req.path of swob instead
    # of it.
    path = req.environ.get('RAW_PATH_INFO', req.path)
    if req.query_string:
        path += '?' + req.query_string
    if '?' in path:
        path, args = path.split('?', 1)
        qstr = ''
        qdict = dict(urlparse.parse_qsl(args, keep_blank_values=True))
        #
        # List of  sub-resources that must be maintained as part of the HMAC
        # signature string.
        #
        keywords = sorted(['acl', 'delete', 'lifecycle', 'location', 'logging',
            'notification', 'partNumber', 'policy', 'requestPayment',
            'torrent', 'uploads', 'uploadId', 'versionId', 'versioning',
            'versions', 'website'])
        for key in qdict:
            if key in keywords:
                newstr = key
                if qdict[key]:
                    newstr = newstr + '=%s' % qdict[key]

                if qstr == '':
                    qstr = newstr
                else:
                    qstr = qstr + '&%s' % newstr

        if qstr != '':
            return "%s%s?%s" % (buf, path, qstr)

    return buf + path

def swift_acl_translate(acl, group='', user='', xml=False):
    """
    Takes an S3 style ACL and returns a list of header/value pairs that
    implement that ACL in Swift, or "Unsupported" if there isn't a way to do
    that yet.
    """
    swift_acl = {}
    swift_acl['public-read'] = [['HTTP_X_CONTAINER_READ', '.r:*,.rlistings']]
    # Swift does not support public write:
    # https://answers.launchpad.net/swift/+question/169541
    swift_acl['public-read-write'] = [['HTTP_X_CONTAINER_WRITE', '.r:*'],
                                      ['HTTP_X_CONTAINER_READ',
                                       '.r:*,.rlistings']]

    #TODO: if there's a way to get group and user, this should work for
    # private:
    #swift_acl['private'] = [['HTTP_X_CONTAINER_WRITE',  group + ':' + user], \
    #                  ['HTTP_X_CONTAINER_READ', group + ':' + user]]
    swift_acl['private'] = [['HTTP_X_CONTAINER_WRITE', '.'],
                            ['HTTP_X_CONTAINER_READ', '.']]
    if xml:
        # We are working with XML and need to parse it
        dom = parseString(acl)
        acl = 'unknown'
        for grant in dom.getElementsByTagName('Grant'):
            permission = grant.getElementsByTagName('Permission')[0]\
                .firstChild.data
            grantee = grant.getElementsByTagName('Grantee')[0]\
                .getAttributeNode('xsi:type').nodeValue
            if permission == "FULL_CONTROL" and grantee == 'CanonicalUser' and\
                    acl != 'public-read' and acl != 'public-read-write':
                acl = 'private'
            elif permission == "READ" and grantee == 'Group' and\
                    acl != 'public-read-write':
                acl = 'public-read'
            elif permission == "WRITE" and grantee == 'Group':
                acl = 'public-read-write'
            else:
                acl = 'unsupported'

    if acl == 'authenticated-read':
        return "Unsupported"
    elif acl not in swift_acl:
        return "InvalidArgument"

    return swift_acl[acl]


def validate_bucket_name(name):
    """
    Validates the name of the bucket against S3 criteria,
    http://docs.amazonwebservices.com/AmazonS3/latest/BucketRestrictions.html
    True if valid, False otherwise
    """

    if '_' in name or len(name) < 3 or len(name) > 63 or not name[-1].isalnum():
        # Bucket names should not contain underscores (_)
        # Bucket names must end with a lowercase letter or number
        # Bucket names should be between 3 and 63 characters long
        return False
    elif '.-' in name or '-.' in name or '..' in name or not name[0].isalnum():
        # Bucket names cannot contain dashes next to periods
        # Bucket names cannot contain two adjacent periods
        # Bucket names Must start with a lowercase letter or a number
        return False
    elif re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
                  "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", name):
        # Bucket names cannot be formatted as an IP Address
        return False
    else:
        return True

class BaseController(WSGIContext):
    VERSIONS_BUCKET_SUFFIX = '_versioned'

    def __init__(self, env, app, token):
        super(BaseController, self).__init__(app)
        env['HTTP_X_AUTH_TOKEN'] = token

    def _app_call(self, env):
        copy_env = env.copy()
        self._set_path_info(copy_env)
        return super(BaseController, self)._app_call(copy_env)

    def _set_path_info(self, env):
        account, container, object = self.account_name, None, None
        if hasattr(self, 'container_name'):
            container = self.container_name
            if hasattr(self, 'object_name'):
                object = self.object_name
        path = '/'.join(filter(None, [account, container, object]))
        env['PATH_INFO'] = '/v1/%s' % path

    def _versioned_object_of(self, key, last_modified, deleted=False):
        """
        Get versioned key given either a last_modified string (ISO datetime
        format) or datetime which will be its versionId
        """
        # TODO regex last_modified
        version_id = to_timestamp(last_modified)
        return self._versioned_object_at(key, version_id, deleted)

    def _versioned_object_at(self, key, version_id, deleted=False):
        """
        Get versioned object get given the versionId
        """
        return "%s$%s$%s" % (key, version_id, "0" if deleted else "1")

    def _versioned_bucket_of(self, bucket):
        """
        Get versioned bucket name of another
        """
        return bucket + self.VERSIONS_BUCKET_SUFFIX

    def no_need_versions(self, object_name):
        return object_name.startswith('meta/')


class ServiceController(BaseController):
    """
    Handles account level requests.
    """
    def __init__(self, env, app, token, account_name, **kwargs):
        super(ServiceController, self).__init__(env, app, token)
        self.account_name = unquote(account_name)

    def GET(self, env, start_response):
        """
        Handle GET Service request
        """
        env['QUERY_STRING'] = 'format=json'

        body_iter = self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_OK:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            else:
                return get_err_response('InvalidURI')

        containers = loads(''.join(list(body_iter)))
        # we don't keep the creation time of a bucket (s3cmd doesn't
        # work without that) so we use something bogus.
        body = '<?xml version="1.0" encoding="UTF-8"?>' \
               '<ListAllMyBucketsResult ' \
               'xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
               '<Buckets>%s</Buckets>' \
               '</ListAllMyBucketsResult>' \
               % ("".join(['<Bucket><Name>%s</Name><CreationDate>'
                           '2009-02-03T16:45:09.000Z</CreationDate></Bucket>'
                           % xml_escape(i['name']) for i in containers]))
        resp = Response(status=HTTP_OK, content_type='application/xml',
                        body=body)
        return resp


class BucketController(BaseController):
    """
    Handles bucket request.
    """
    def __init__(self, env, app, token, account_name, container_name, **kwargs):
        super(BucketController, self).__init__(env, app, token)

        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)

        conf = kwargs.get('conf', {})
        self.location = conf.get('location', 'US')

    def fetch_last_modified_time(self, env, key):
        env['REQUEST_METHOD'] = 'GET'
        env['QUERY_STRING'] = 'format=json&limit=1&prefix=%s' % quote(key)
        body_iter = self._app_call(env)
        try:
            # ISO format: '2013-05-20T16:20:27.690370' microseconds included
            return loads(''.join(list(body_iter)))[0]['last_modified']
        except:
            return None

    def fetch_versions(self, env, key):
        self.container_name = self._versioned_bucket_of(self.container_name)
        env['REQUEST_METHOD'] = 'GET'
        env['QUERY_STRING'] = 'format=json&limit=10000&prefix=%s' % quote(key)
        body_iter = self._app_call(env)
        try:
            files = loads(''.join(list(body_iter)))
            versions = []
            for o in files:
                parts = to_str(o['name']).split('$')
                versions.append({'deleted': parts[-1] == '0',
                                 'version': parts[-2]})
            return sorted(versions,
                lambda a,b: cmp(a['version'], b['version']))
        except:
            return []

    def GET(self, env, start_response):
        """
        Handle GET Bucket (List Objects) request
        """
        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        if 'max-keys' in args:
            if args.get('max-keys').isdigit() is False:
                return get_err_response('InvalidArgument')

        max_keys = min(int(args.get('max-keys', MAX_BUCKET_LISTING)),
                       MAX_BUCKET_LISTING)

        if 'versioning' in args:
            body = ('<VersioningConfiguration '
                    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                    '<Status>Enabled</Status>'
                    '</VersioningConfiguration>')
            return Response(body=body, content_type="text/plain")

        if 'location' in args:
            body = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<LocationConstraint '
                    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"')
            if self.location == 'US':
                body += '/>'
            else:
                body += ('>%s</LocationConstraint>' % self.location)
            return Response(body=body, content_type='application/xml')

        if 'logging' in args:
            # logging disabled
            body = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<BucketLoggingStatus '
                    'xmlns="http://doc.s3.amazonaws.com/2006-03-01" />')
            return Response(body=body, content_type='application/xml')

        if 'acl' not in args:
            # acl request sent with format=json etc confuses swift
            env['QUERY_STRING'] = 'format=json&limit=%s' % (max_keys + 1)
        if 'marker' in args:
            env['QUERY_STRING'] += '&marker=%s' % quote(args['marker'])
        if 'prefix' in args:
            env['QUERY_STRING'] += '&prefix=%s' % quote(args['prefix'])
        if 'delimiter' in args:
            env['QUERY_STRING'] += '&delimiter=%s' % quote(args['delimiter'])

        body_iter = self._app_call(env)
        status = self._get_status_int()
        headers = dict(self._response_headers)

        if is_success(status) and 'acl' in args:
            return get_acl(self.account_name, headers)

        if status != HTTP_OK:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            else:
                return get_err_response('InvalidURI')

        objects = loads(''.join(list(body_iter)))

        if 'versions' in args:
            self.container_name = self._versioned_bucket_of(self.container_name)
            body_iter = self._app_call(env)
            status = self._get_status_int()
            if status != HTTP_OK:
                if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return get_err_response('AccessDenied')
                elif status == HTTP_NOT_FOUND:
                    return get_err_response('NoSuchBucket')
                else:
                    return get_err_response('InvalidURI')
            vobjects = loads(''.join(list(body_iter)))
            body = self._list_versions_results(max_keys, args, objects,
                                               vobjects)
        else:
            body = self._list_bucket_results(max_keys, args, objects)

        return Response(body=body, content_type='application/xml')

    def _list_versions_results(self, max_keys, args, objects, vobjects):
        currents = {to_str(o['name']): to_timestamp(o['last_modified'])
                    for o in objects if 'subdir' not in o}
        # Current objects
        objs = [('<Version>'
                    '<Key>%s</Key>'
                    '<VersionId>%s</VersionId>'
                    '<IsLatest>%s</IsLatest>'
                    '<LastModified>%sZ</LastModified>'
                    '<ETag>&quot;%s&quot;</ETag>'
                    '<Size>%s</Size>'
                    '<StorageClass>STANDARD</StorageClass>'
                    '<Owner>'
                        '<ID>%s</ID>'
                        '<DisplayName>%s</DisplayName>'
                    '</Owner>'
                '</Version>') % (
                xml_escape(to_str(o['name'])),
                to_timestamp(o['last_modified']),
                'true',
                o['last_modified'],
                o['hash'],
                o['bytes'],
                self.account_name, self.account_name)
                for o in objects if 'subdir' not in o]
        # Versioned objects
        token_separator = '$'
        for o in vobjects:
            if 'subdir' in o:
                continue
            parts = to_str(o['name']).split(token_separator)
            deleted = parts[-1] == '0'
            timestamp = parts[-2]
            name = token_separator.join(parts[0:-2])
            if name in currents and timestamp == currents[name]:
                continue
            if deleted:
                objs.append(
                    '<DeleteMarker>'
                        '<Key>%s</Key>'
                        '<VersionId>%s</VersionId>'
                        '<IsLatest>%s</IsLatest>'
                        '<LastModified>%sZ</LastModified>'
                    '</DeleteMarker>' % (
                    name,
                    timestamp,
                    'false', # FIXME
                    o['last_modified']
                ))
            else:
                objs.append(
                    '<Version>'
                        '<Key>%s</Key>'
                        '<VersionId>%s</VersionId>'
                        '<IsLatest>%s</IsLatest>'
                        '<LastModified>%sZ</LastModified>'
                        '<ETag>&quot;%s&quot;</ETag>'
                        '<Size>%s</Size>'
                        '<StorageClass>STANDARD</StorageClass>'
                        '<Owner>'
                            '<ID>%s</ID>'
                            '<DisplayName>%s</DisplayName>'
                        '</Owner>'
                    '</Version>' % (
                    name,
                    timestamp,
                    'false',
                    o['last_modified'],
                    o['hash'],
                    o['bytes'],
                    self.account_name, self.account_name
                ))
        common_prefixes = [
            '<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>' %
            xml_escape(to_str(i['subdir']))
            for i in objects[:max_keys] if 'subdir' in i]
        xml = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01">'
                '<Prefix>%s</Prefix>'
                '<KeyMarker>%s</KeyMarker>'
                '<VersionIdMarker>%s</VersionIdMarker>'
                '<Delimiter>%s</Delimiter>'
                '<IsTruncated>%s</IsTruncated>'
                '<MaxKeys>%s</MaxKeys>'
                '<Name>%s</Name>'
                '%s'
                '%s'
            '</ListVersionsResult>' % (
            xml_escape(args.get('prefix', '')),
            xml_escape(args.get('key-marker', '')),
            xml_escape(args.get('version-id-marker', '')),
            xml_escape(args.get('delimiter', '')),
            'true' if len(objs) >= (max_keys + 1) else 'false',
            max_keys,
            xml_escape(self.container_name.split(self.VERSIONS_BUCKET_SUFFIX)[0]),
            "".join(objs),
            "".join(common_prefixes)
        ))
        return xml

    def _list_bucket_results(self, max_keys, args, objects):
        contents = [(
            '<Contents>'
                '<Key>%s</Key>'
                '<LastModified>%sZ</LastModified>'
                '<ETag>%s</ETag>'
                '<Size>%s</Size>'
                '<StorageClass>STANDARD</StorageClass>'
                '<Owner>'
                    '<ID>%s</ID>'
                    '<DisplayName>%s</DisplayName>'
                '</Owner>'
            '</Contents>') % (
            xml_escape(to_str(i['name'])),
            i['last_modified'],
            i['hash'],
            i['bytes'],
            self.account_name, self.account_name)
            for i in objects[:max_keys] if 'subdir' not in i]
        common_prefixes = [
            '<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>' %
            xml_escape(to_str(i['subdir']))
            for i in objects[:max_keys] if 'subdir' in i]
        xml = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01">'
                '<Prefix>%s</Prefix>'
                '<Marker>%s</Marker>'
                '<Delimiter>%s</Delimiter>'
                '<IsTruncated>%s</IsTruncated>'
                '<MaxKeys>%s</MaxKeys>'
                '<Name>%s</Name>'
                '%s'
                '%s'
            '</ListBucketResult>' % (
            xml_escape(args.get('prefix', '')),
            xml_escape(args.get('marker', '')),
            xml_escape(args.get('delimiter', '')),
            'true' if max_keys > 0 and len(objects) == (max_keys + 1) else
            'false',
            max_keys,
            xml_escape(self.container_name),
            "".join(contents),
            "".join(common_prefixes)
        ))
        return xml

    def PUT(self, env, start_response):
        """
        Handle PUT Bucket request
        """
        if 'HTTP_X_AMZ_ACL' in env:
            amz_acl = env['HTTP_X_AMZ_ACL']
            # Translate the Amazon ACL to something that can be
            # implemented in Swift, 501 otherwise. Swift uses POST
            # for ACLs, whereas S3 uses PUT.
            del env['HTTP_X_AMZ_ACL']
            if 'QUERY_STRING' in env:
                del env['QUERY_STRING']

            translated_acl = swift_acl_translate(amz_acl)
            if translated_acl == 'Unsupported':
                return get_err_response('Unsupported')
            elif translated_acl == 'InvalidArgument':
                return get_err_response('InvalidArgument')

            for header, acl in translated_acl:
                env[header] = acl

        if 'CONTENT_LENGTH' in env:
            content_length = env['CONTENT_LENGTH']
            try:
                content_length = int(content_length)
            except (ValueError, TypeError):
                return get_err_response('InvalidArgument')
            if content_length < 0:
                return get_err_response('InvalidArgument')

        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
            if 'acl' in args:
                # We very likely have an XML-based ACL request.
                body = env['wsgi.input'].readline().decode()
                translated_acl = swift_acl_translate(body, xml=True)
                if translated_acl == 'Unsupported':
                    return get_err_response('Unsupported')
                elif translated_acl == 'InvalidArgument':
                    return get_err_response('InvalidArgument')
                for header, acl in translated_acl:
                    env[header] = acl
                env['REQUEST_METHOD'] = 'POST'

        body_iter = self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_CREATED and status != HTTP_NO_CONTENT:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_ACCEPTED:
                return get_err_response('BucketAlreadyExists')
            else:
                return get_err_response('InvalidURI')

        resp = Response(status=HTTP_OK,
                        headers={'Location': self.container_name})

        # Created versions bucket
        self.container_name = self._versioned_bucket_of(self.container_name)
        self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_CREATED and status != HTTP_NO_CONTENT:
            # Remove the one just created
            env['REQUEST_METHOD'] = 'DELETE'
            self.container_name = self.container_name.split(
                                        self.VERSIONS_BUCKET_SUFFIX)[0]
            self._app_call(env)
            # If we fail deleting, nothing we can do (try it several times?)

            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_ACCEPTED:
                return get_err_response('BucketAlreadyExists')
            else:
                return get_err_response('InvalidURI')

        return resp

    def DELETE(self, env, start_response):
        """
        Handle DELETE Bucket request
        """
        body_iter = self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_NO_CONTENT:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            elif status == HTTP_CONFLICT:
                return get_err_response('BucketNotEmpty')
            else:
                return get_err_response('InvalidURI')

        resp = Response()
        resp.status = HTTP_NO_CONTENT
        return resp

    def _delete_multiple_objects(self, env):
        def _object_key_iter(xml):
            dom = parseString(xml)
            delete = dom.getElementsByTagName('Delete')[0]
            for obj in delete.getElementsByTagName('Object'):
                key = obj.getElementsByTagName('Key')[0].firstChild.data
                version = None
                if obj.getElementsByTagName('VersionId').length > 0:
                    version = obj.getElementsByTagName('VersionId')[0]\
                        .firstChild.data
                yield (key, version)

        def _get_deleted_elem(key):
            return '  <Deleted>\r\n' \
                   '    <Key>%s</Key>\r\n' \
                   '  </Deleted>\r\n' % (key)

        def _get_err_elem(key, err_code, message):
            return '  <Error>\r\n' \
                   '    <Key>%s</Key>\r\n' \
                   '    <Code>%s</Code>\r\n' \
                   '    <Message>%s</Message>\r\n' \
                   '  </Error>\r\n'  % (key, err_code, message)

        body = '<?xml version="1.0" encoding="UTF-8"?>\r\n' \
               '<DeleteResult ' \
               'xmlns="http://doc.s3.amazonaws.com/2006-03-01">\r\n'
        xml = env['wsgi.input'].read()
        for key, version in _object_key_iter(xml):
            if version is not None:
                # TODO: delete the specific version of the object
                return get_err_response('Unsupported')

            tmp_env = dict(env)
            del tmp_env['QUERY_STRING']
            tmp_env['CONTENT_LENGTH'] = '0'
            tmp_env['REQUEST_METHOD'] = 'DELETE'
            controller = ObjectController(tmp_env, self.app,
                                          env['HTTP_X_AUTH_TOKEN'],
                                          self.account_name,
                                          self.container_name, key)
            controller._app_call(tmp_env)
            status = controller._get_status_int()

            if status == HTTP_NO_CONTENT or status == HTTP_NOT_FOUND:
                body += _get_deleted_elem(key)
            else:
                if status == HTTP_UNAUTHORIZED:
                    body += _get_err_elem(key, 'AccessDenied', 'Access Denied')
                else:
                    body += _get_err_elem(key, 'InvalidURI', 'Invalid URI')

        body += '</DeleteResult>\r\n'
        return Response(status=HTTP_OK, body=body)

    def POST(self, env, start_response):
        """
        Handle POST Bucket (Delete/Upload Multiple Objects) request
        """
        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        if 'delete' in args:
            return self._delete_multiple_objects(env)

        if 'uploads' in args:
            # Pass it through, the s3multi upload helper will handle it.
            return self.app(env,start_response)

        if 'uploadId' in args:
            # Pass it through, the s3multi upload helper will handle it.
            return self.app(env, start_response)

        return get_err_response('Unsupported')


class ObjectController(BaseController):
    """
    Handles requests on objects
    """
    def __init__(self, env, app, token, account_name, container_name,
                 object_name, **kwargs):
        super(ObjectController, self).__init__(env, app, token)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)

    def GETorHEAD(self, env, start_response):
        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        # Let s3multi handle it.
        if 'uploadId' in args:
            return self.app(env, start_response)

        if 'acl' in args:
            # ACL requests need to make a HEAD call rather than GET
            env['REQUEST_METHOD'] = 'HEAD'
            env['SCRIPT_NAME'] = ''
            env['QUERY_STRING'] = ''

        if 'versionId' in args:
            self.container_name = self._versioned_bucket_of(self.container_name)
            self.object_name = self._versioned_object_at(self.object_name,
                                                         args['versionId'])

        app_iter = self._app_call(env)
        status = self._get_status_int()
        headers = dict(self._response_headers)

        if env['REQUEST_METHOD'] == 'HEAD':
            app_iter = None

        if is_success(status):
            if 'acl' in args:
                # Method must be GET or the body wont be returned to the caller
                env['REQUEST_METHOD'] = 'GET'
                return get_acl(self.account_name, headers)

            new_hdrs = {}
            for key, val in headers.iteritems():
                _key = key.lower()
                if _key.startswith('x-object-meta-'):
                    new_hdrs['x-amz-meta-' + key[14:]] = val
                elif _key in ('content-length', 'content-type',
                              'content-range', 'content-encoding',
                              'etag', 'last-modified'):
                    new_hdrs[key] = val
            return Response(status=status, headers=new_hdrs, app_iter=app_iter)
        elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
            return get_err_response('AccessDenied')
        elif status == HTTP_NOT_FOUND:
            return get_err_response('NoSuchKey')
        else:
            return get_err_response('InvalidURI')

    def HEAD(self, env, start_response):
        """
        Handle HEAD Object request
        """
        return self.GETorHEAD(env, start_response)

    def GET(self, env, start_response):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(env, start_response)

    def PUT(self, env, start_response):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        for key, value in env.items():
            if key.startswith('HTTP_X_AMZ_META_'):
                del env[key]
                env['HTTP_X_OBJECT_META_' + key[16:]] = value
            elif key == 'HTTP_CONTENT_MD5':
                if value == '':
                    return get_err_response('InvalidDigest')
                try:
                    env['HTTP_ETAG'] = value.decode('base64').encode('hex')
                except:
                    return get_err_response('InvalidDigest')
                if env['HTTP_ETAG'] == '':
                    return get_err_response('SignatureDoesNotMatch')
            elif key == 'HTTP_X_AMZ_COPY_SOURCE':
                if '?versionId=' in value:
                    # Copy from older version
                    bucket, obj = split_path(value, 2, rest_with_last=True)
                    copy_from = '/' + self._versioned_bucket_of(bucket) + '/' +\
                        self._versioned_object_at(*obj.split('?versionId=', 1))
                    env['HTTP_X_COPY_FROM'] = copy_from
                else:
                    env['HTTP_X_COPY_FROM'] = value

        # 1) Real PUT
        self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_CREATED:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            elif status == HTTP_UNPROCESSABLE_ENTITY:
                return get_err_response('InvalidDigest')
            else:
                return get_err_response('InvalidURI')

        if 'HTTP_X_COPY_FROM' in env:
            body = '<CopyObjectResult><LastModified>%sZ</LastModified>' \
                   '<ETag>"%s"</ETag></CopyObjectResult>' % \
                   (self._response_header_value('last-modified'),
                    self._response_header_value('etag'))
            res = Response(status=HTTP_OK, body=body)
        else:
            res = Response(status=HTTP_OK,
                           etag=self._response_header_value('etag'))

        if self.no_need_versions(self.object_name):
            return res

        # 2) List Bucket to get timestamp with microseconds precision
        # last-modified header only has seconds precision
        tmp_env = env.copy()
        bc = BucketController(tmp_env, self.app, env['HTTP_X_AUTH_TOKEN'],
                              self.account_name, self.container_name)
        last_modified = bc.fetch_last_modified_time(tmp_env, self.object_name)

        # 3) and finally put versioned object
        env['HTTP_X_COPY_FROM'] = '/' + self.container_name + \
                                  '/' + self.object_name
        env['CONTENT_LENGTH'] = '0'
        if last_modified is None:
            last_modified = self._response_header_value('last-modified')
        self.container_name = self._versioned_bucket_of(self.container_name)
        self.object_name = self._versioned_object_of(self.object_name,
                                                     last_modified)
        self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_CREATED:
            # Delete file
            env['REQUEST_METHOD'] = 'DELETE'
            self.container_name, self.object_name = \
                split_path(env['HTTP_X_COPY_FROM'], 2, rest_with_last=True)
            del env['HTTP_X_COPY_FROM']
            del env['CONTENT_LENGTH']
            self._app_call(env)

            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            elif status == HTTP_UNPROCESSABLE_ENTITY:
                return get_err_response('InvalidDigest')
            else:
                return get_err_response('InvalidURI')

        return res

    def POST(self, env, start_response):
        return get_err_response('AccessDenied')

    def DELETE(self, env, start_response):
        """
        Handle DELETE Object request
        """
        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
            del env['QUERY_STRING']
        else:
            args = {}
        if 'versionId' in args:
            tmp_env = env.copy()
            bc = BucketController(tmp_env, self.app, env['HTTP_X_AUTH_TOKEN'],
                                  self.account_name, self.container_name)
            versions = bc.fetch_versions(tmp_env, self.object_name)
            if not versions:
                # FIXME to delete the current file without having a versioned
                # file. This should not happen, but it does
                tmp_env = env.copy()
                bc = BucketController(tmp_env, self.app,
                                      env['HTTP_X_AUTH_TOKEN'],
                                      self.account_name, self.container_name)
                time = to_timestamp(
                    bc.fetch_last_modified_time(tmp_env, self.object_name))
                if time == args['versionId']:
                    self._app_call(env)
                    return Response(status=HTTP_NO_CONTENT)
                return get_err_response('NoSuchKey')

            if versions[-1]['version'] == args['versionId']:
                # delete also from the real bucket
                self._app_call(env)
            # Delete the versioned file
            self.container_name = self._versioned_bucket_of(self.container_name)
            version = None
            for v in versions:
                if v['version'] == args['versionId']:
                    version = v
                    break
            if not version:
                return get_err_response('NoSuchKey')
            self.object_name = self._versioned_object_at(self.object_name,
                                                         version['version'],
                                                         version['deleted'])
        self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_NO_CONTENT:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchKey')
            else:
                return get_err_response('InvalidURI')

        if 'versionId' in args or self.no_need_versions(self.object_name):
            # For versioned deletions, we won't put a versioned version of the
            # file we are deleting
            return Response(status=HTTP_NO_CONTENT)

        env['REQUEST_METHOD']= 'PUT'
        env['CONTENT_TYPE'] = 'text/plain'
        env['CONTENT_LENGTH'] = '0'
        self.container_name = self._versioned_bucket_of(self.container_name)
        self.object_name = self._versioned_object_of(self.object_name,
                                                     datetime.datetime.now(),
                                                     deleted=True)
        self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_CREATED:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchKey')
            elif status == HTTP_UNPROCESSABLE_ENTITY:
                return get_err_response('InvalidDigest')
            else:
                return get_err_response('InvalidURI')

        resp = Response(status=HTTP_NO_CONTENT)
        return resp


class Swift3Middleware(object):
    """Swift3 S3 compatibility midleware"""
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='swift3')

    def get_controller(self, env, path):
        container, obj = split_path(path, 0, 2, True)
        d = dict(container_name=container, object_name=obj)

        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        if container and obj:
            if env['REQUEST_METHOD'] == 'POST':
                if 'uploads' or 'uploadId' in args:
                    return BucketController, d
            return ObjectController, d
        elif container:
            return BucketController, d

        return ServiceController, d

    def __call__(self, env, start_response):
        try:
            return self.handle_request(env, start_response)
        except Exception, e:
            self.logger.exception(e)
        return get_err_response('ServiceUnavailable')(env, start_response)

    def handle_request(self, env, start_response):
        req = Request(env)
        self.logger.debug('Calling Swift3 Middleware')
        self.logger.debug(req.__dict__)

        if 'AWSAccessKeyId' in req.params:
            try:
                req.headers['Date'] = req.params['Expires']
                req.headers['Authorization'] = \
                    'AWS %(AWSAccessKeyId)s:%(Signature)s' % req.params
            except KeyError:
                return get_err_response('InvalidArgument')(env, start_response)

        if 'Authorization' not in req.headers:
            return self.app(env, start_response)

        try:
            keyword, info = req.headers['Authorization'].split(' ')
        except:
            return get_err_response('AccessDenied')(env, start_response)

        if keyword != 'AWS':
            return get_err_response('AccessDenied')(env, start_response)

        try:
            account, signature = info.rsplit(':', 1)
        except:
            return get_err_response('InvalidArgument')(env, start_response)

        try:
            controller, path_parts = self.get_controller(env, req.path)
        except ValueError:
            return get_err_response('InvalidURI')(env, start_response)

        if 'Date' in req.headers:
            date = email.utils.parsedate(req.headers['Date'])
            if date is None and 'Expires' in req.params:
                try:
                    d = email.utils.formatdate(float(req.params['Expires']))
                    date = email.utils.parsedate(d)
                except ValueError:
                    pass

            if date is None:
                return get_err_response('AccessDenied')(env, start_response)

            d1 = datetime.datetime(*date[0:6])
            d2 = datetime.datetime.utcnow()
            epoch = datetime.datetime(1970, 1, 1, 0, 0, 0, 0)

            if d1 < epoch:
                return get_err_response('AccessDenied')(env, start_response)

            delta = datetime.timedelta(seconds=60 * 5)
            if d1 - d2 > delta or d2 - d1 > delta:
                return get_err_response('RequestTimeTooSkewed')(env,
                                                                start_response)

        token = base64.urlsafe_b64encode(canonical_string(req))
        controller = controller(env, self.app, token, account, conf=self.conf,
                                **path_parts)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(env, start_response)
        else:
            return get_err_response('InvalidURI')(env, start_response)

        return res(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def swift3_filter(app):
        return Swift3Middleware(app, conf)

    return swift3_filter
