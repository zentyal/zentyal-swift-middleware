# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 Zentyal SL

# This source code is based s3_token.py
# See them for their copyright.

"""
This WSGI component:

* Get a request from the swift3 middleware with an S3 Authorization
  access key.
* Validate s3 token against harcoded conf values
* Transform the account name to AUTH_%(tenant_name).

"""

import webob
import base64
import hmac

from hashlib import sha1

from keystone.common import utils as keystone_utils
from swift.common import utils as swift_utils


PROTOCOL_NAME = 'S3 Token Authentication'


class ServiceError(Exception):
    pass


class S3Auth(object):
    """Auth Middleware that handles S3 authenticating client calls."""

    def __init__(self, app, conf):
        """Common initialization code."""
        self.app = app
        self.logger = swift_utils.get_logger(conf, log_route='s3token')
        self.logger.debug('Starting the %s component' % PROTOCOL_NAME)
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH_')

        # Credentials and tenant_id
        self.access_id = conf.get('access_id')
        self.access_secret = conf.get('access_secret')
        self.tenant_id = conf.get('tenant_id')

    def deny_request(self, code):
        error_table = {
            'AccessDenied': (401, 'Access denied'),
            'InvalidURI': (400, 'Could not parse the specified URI'),
        }
        resp = webob.Response(content_type='text/xml')
        resp.status = error_table[code][0]
        resp.body = error_table[code][1]
        resp.body = ('<?xml version="1.0" encoding="UTF-8"?>\r\n'
                     '<Error>\r\n  <Code>%s</Code>\r\n  '
                     '<Message>%s</Message>\r\n</Error>\r\n' %
                     (code, error_table[code][1]))
        return resp


    def __call__(self, environ, start_response):
        """Handle incoming request. authenticate and send downstream."""
        req = webob.Request(environ)
        self.logger.debug('Calling S3Auth middleware.')

        try:
            parts = swift_utils.split_path(req.path, 1, 4, True)
            version, account, container, obj = parts
        except ValueError:
            msg = 'Not a path query, skipping.'
            self.logger.debug(msg)
            return self.app(environ, start_response)

        # Read request signature and access id.
        if 'Authorization' not in req.headers:
            msg = 'No Authorization header. skipping.'
            self.logger.debug(msg)
            return self.app(environ, start_response)

        token = req.headers.get('X-Auth-Token',
                                req.headers.get('X-Storage-Token'))
        if not token:
            msg = 'You did not specify a auth or a storage token. skipping.'
            self.logger.debug(msg)
            return self.app(environ, start_response)

        auth_header = req.headers['Authorization']
        try:
            access, signature = auth_header.split(' ')[-1].rsplit(':', 1)
        except ValueError:
            msg = 'You have an invalid Authorization header: %s'
            self.logger.debug(msg % (auth_header))
            return self.deny_request('InvalidURI')(environ, start_response)

        # NOTE(chmou): This is to handle the special case with nova
        # when we have the option s3_affix_tenant. We will force it to
        # connect to another account than the one
        # authenticated. Before people start getting worried about
        # security, I should point that we are connecting with
        # username/token specified by the user but instead of
        # connecting to its own account we will force it to go to an
        # another account. In a normal scenario if that user don't
        # have the reseller right it will just fail but since the
        # reseller account can connect to every account it is allowed
        # by the swift_auth middleware.
        force_tenant = None
        if ':' in access:
            access, force_tenant = access.split(':')

        # Check authentication
        msg = base64.urlsafe_b64decode(str(token))
        key = str(self.access_secret)
        signed = base64.encodestring(hmac.new(key, msg, sha1).digest()).strip()

        if not keystone_utils.auth_str_equal(signature, signed) or \
           not keystone_utils.auth_str_equal(access, self.access_id):
            self.logger.debug('Failed to check credentials for %s' % access)
            return self.deny_request('AccessDenied')(environ, start_response)


        # Fill PATH_INFO and return
        self.logger.debug('Connecting with tenant: %s' % (self.tenant_id))
        new_tenant_name = '%s%s' % (self.reseller_prefix, self.tenant_id)
        environ['PATH_INFO'] = environ['PATH_INFO'].replace(account,
                                                            new_tenant_name)
        return self.app(environ, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return S3Auth(app, conf)
    return auth_filter
