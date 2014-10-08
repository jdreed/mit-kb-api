from functools import wraps, partial
import flask
import jinja2
import json
import logging
import sys
import os
import time
import re
import xml.etree.ElementTree as xmletree
import html5lib
import traceback
from collections import defaultdict
#from flask.ext.restful import Api, Resource, reqparse, abort, fields, marshal
from werkzeug.exceptions import (HTTPException, Gone, InternalServerError,
                                 NotImplemented, NotFound, MethodNotAllowed,
                                 Forbidden, Unauthorized, NotAcceptable,
                                 BadRequest)
# For Lock
import threading
import errno

#from confluence.shortcode import code2id
#from confluence.rpc import Session, RemoteException
from xml.sax import saxutils

from .config import APIConfig as config
from . import auth
from .models import ValidationError
from .database import db

logger = logging.getLogger('kb_api.admin')
#config = APIConfig()
thread_lock = threading.Lock()
#confluence_session = Session(config.get('Connection', 'host'))
#confluence_session.login(config.get('Connection', 'username'),
#                         config.get('Connection', 'password'))

def html_escape(thing):
    if isinstance(thing, dict):
        return {k: html_escape(v) for k,v in thing.items()}
    if isinstance(thing, str):
        return saxutils.escape(thing)
    return thing


log_level = config.get('Logging', 'level', 'WARNING')
log_file = config.get('Logging', 'file', None)
if log_file is not None:
    try:
        hdlr = logging.FileHandler(log_file)
        hdlr.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(message)s'))
        logging.getLogger('kb_api').addHandler(hdlr)
    except IOError as e:
        print >>sys.stderr, "Warning: Cannot log to file: {0}".format(e)
    logging.getLogger('kb_api').setLevel(getattr(logging, log_level))

#logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
#logging.getLogger('sqlalchemy.engine').addHandler(hdlr)

app = flask.Flask(__name__,
                  template_folder=config.get('Admin', 'templates', 'templates'))

app.config['SQLALCHEMY_DATABASE_URI'] = config.get('Authentication', 'db_uri')
db.init_app(app)

app.jinja_env.undefined = jinja2.StrictUndefined

def authenticated_route(f=None, require_admin=False, optional=False):
    if f is None:
        return partial(authenticated_route, require_admin=require_admin,
                       optional=optional)
    if require_admin and optional:
        raise TypeError('Cannot mix optional=True and require_admin=True')
    @wraps(f)
    def auth_decorator(*args, **kwargs):
        user = auth.X509RemoteUser(flask.request.environ)
        logger.debug('user=%s', user)
        if not optional and not user.authenticated:
            raise Exception("User not found")
#            logger.debug("returning 401")
#            flask.abort(403)
        if require_admin and not user.is_administrator: 
            logger.debug("returning 403")
            flask.abort(403)
        kwargs['remote_user'] = user
        return f(*args, **kwargs)
    return auth_decorator

def extract_formdata(f=None, required=tuple()):
    if f is None:
        return partial(extract_formdata, required=required)
    @wraps(f)
    def auth_decorator(*args, **kwargs):
        if flask.request.method == 'POST':
            kwargs['formdata'] = flask.request.form
            if not all([x in kwargs['formdata'] for x in required]):
                raise BadRequest('form data missing')
        return f(*args, **kwargs)
    return auth_decorator

#todo: handle undefinederror?

#@app.before_first_request
#def first_request():
#    # Store the config somewhere other things can get to it
#    setattr(flask.g, '_api_config', config)

#    try:
#        with auth.AuthenticationContext() as ctx:
#            _ = auth.Statuses.ACTIVE
#    except auth.AuthenticationError:
#        return "hi"
#        flask.abort(403)

@app.errorhandler(403)
def fix_403(exception, **kwargs):
    # Safari's behavior is broken.  When a re-negotiated URL (e.g. for
    # SSLVerifyClient require in a directory context) returns 403,
    # Safari interprets that as "You didn't supply the correct cert"
    # and prompts the user for the cert continuously, never
    # succeeding.  If there's an identity preference, it fails
    # immediately with "could not establish secure connect"
    # So return 200.
    code = 200 if flask.request.user_agent.browser == "safari" else 403
    return exception, code


@app.errorhandler(500)
def ohnoes(exception, **kwargs):
    if isinstance(exception, auth.DatabaseError):
        return "Database error: {0}".format(exception)
    return "<pre>" + traceback.format_exc() + "</pre>", 500

@app.template_filter('datetime')
def _filter_datetime(value, fmt='long'):
    if fmt == 'shortdate':
        return value.strftime("%m/%d/%y")
    if fmt == 'short':
        return value.strftime("%m/%d/%y %H:%M:%S")
    if fmt == 'c':
        return value.ctime()
    return value.strftime("%Y-%m-%d %H:%M:%S")

@app.route('/setup', methods=['GET', 'POST'])
@extract_formdata(required=('setup_key',))
def setup(formdata={}, **kwargs):
    # We do _not_ authenticate this route, because the DB might not exist
    # so there's nothing to look up.  Create a remote_user object
    # from X509 data (this will raise an exception if there's no data)
    # and use that for this request only.
    remote_user = auth.X509RemoteUser(flask.request.environ,
                                      no_lookup=True)
    filename = config.get('Setup', 'key_file')
    tmplargs = { 'remote_user': remote_user }
    if flask.request.method != 'POST':
        # This is mostly just cosmetic.  Any race conditions will be 
        # caught by the lock below
        if not os.path.exists(filename):
            flask.abort(404)
        return flask.render_template('setup.html', **tmplargs)
    # Avoid race conditions by acquiring a lock before checking the key
    # and removing the file.  Fail with a 503 if there's a race condition.
    # Lock() can't be used in a context-manager in a non-blocking way without
    # rolling our own, and try/finally works just as well
    if not thread_lock.acquire(False):
        flask.abort(503)
    try:
        with open(filename, 'r') as f:
            key = f.read().strip()
        if key == formdata['setup_key']:
            auth.AuthenticationContext.create_tables()
            auth.add_user(username=remote_user.username,
                          email=remote_user.email,
                          real_name=remote_user.real_name,
                          is_admin=True)
            os.remove(filename)
            return flask.redirect(flask.url_for('admin_root'))
        else:
            tmplargs['form_error'] = "Key incorrect."
    except IOError as e:
        logger.exception("Error while reading setup key file: %s", filename)
        if e.errno == errno.ENOENT:
            flask.abort(404)
        # Shouldn't really happen, and is arguably a 500
        if e.errno == errno.EACCES:
            flask.abort(403)
    finally:
        thread_lock.release()
    return flask.render_template('setup.html', **tmplargs)


@app.route('/enroll', methods=['GET'])
@authenticated_route(optional=True)
def enroll_user(remote_user=None, formdata={}, **kwargs):
    if not remote_user.authenticated:
        auth.add_user(username=remote_user.username,
                      email=remote_user.email,
                      real_name=remote_user.real_name,
                      is_admin=False)
    return flask.redirect(flask.url_for('user_root'))

@app.route('/manage', methods=['GET', 'POST'])
@authenticated_route(require_admin=True)
@extract_formdata(required=('owner', 'email', 'description'))
def admin_root(remote_user=None, formdata={}, **kwargs):
    if flask.request.method == 'POST':
        try:
            user = auth.lookup_user(formdata['owner'])
            if user is None:
                user = auth.add_user(username=formdata['owner'])
            auth.add_key(user,
                         email=formdata['email'],
                         description=formdata['description'],
                         auto_approve=True)
        except ValidationError as e:
            kwargs['formdata'] = formdata
            kwargs['form_error'] = e.message
    keys = auth.get_all_keys()
    return flask.render_template('index.html',
                                 title='API Keys',
                                 is_admin=True,
                                 remote_user=remote_user,
                                 all_keys=[k for k in keys if k.status != auth.Statuses.PENDING],
                                 pending_keys=[k for k in keys if k.status == auth.Statuses.PENDING],
                                 **kwargs)

@app.route('/approve', methods=['POST'])
@authenticated_route(require_admin=True)
@extract_formdata(required=('key_id',))
def approve_key(remote_user=None, formdata={}, **kwargs):
    key = auth.lookup_key(formdata['key_id'])
    if key is None:
        raise BadRequest('Key not found.')
    if key.status != auth.Statuses.PENDING:
        raise BadRequest('Key not pending.')
    auth.update_db_object(key,
                          ('status',),
                          {'status': auth.Statuses.ACTIVE})
    return flask.redirect(flask.url_for('admin_root'))

    # SQLAlchemy is not smart enough check if the data is dirty or not,
    # and we don't want to bump the modtime if we don't need to.
    #     # UGH concurrency, fix the freaking context to deal with the session
    #     # correct and commit


@app.route('/manage/edit', methods=['POST'])
@authenticated_route(require_admin=True)
@extract_formdata(required=('key_id',))
def admin_edit_key(remote_user=None, formdata={}, **kwargs):
    key = auth.lookup_key(formdata['key_id'])
    if key is None:
        raise BadRequest('Key not found')
    tmplargs = {'remote_user': remote_user}
    tmplargs['key'] = key
    tmplargs['statuses'] = auth.Statuses.all
    tmplargs['is_admin'] = remote_user.is_administrator
    if formdata.get('edit_key_submit', None) is not None:
        update_vals = formdata.to_dict()
        tmplargs['formdata'] = formdata
        try:
            if formdata['status'] not in auth.Statuses:
                raise ValidationError('status', 'invalid status')
            update_vals['status'] = getattr(auth.Statuses,
                                            formdata['status'])
            update_vals['owner'] = auth.lookup_user(formdata['owner'])
            if update_vals['owner'] is None:
                raise ValidationError('owner', 'owner is missing')
            auth.update_db_object(key,
                                  ('description', 'email', 'owner', 'status'),
                                  update_vals)
            return flask.redirect(flask.url_for('admin_root'))
        except KeyError as e:
            tmplargs['form_error'] = 'Some form values were missing: {0}'.format(e)
        except ValidationError as e:
            tmplargs['form_error'] = e
    return flask.render_template('edit_key.html', **tmplargs);

@app.route('/edit', methods=['POST'])
@authenticated_route
@extract_formdata(required=('key_id',))
def edit_key(remote_user=None, formdata={}, **kwargs):
    key = auth.lookup_key(formdata['key_id'])
    if key is None:
        raise BadRequest('Key not found')
    tmplargs = {'remote_user': remote_user}
    tmplargs['key'] = key
    tmplargs['statuses'] = auth.Statuses.all
    tmplargs['is_admin'] = False
    tmplargs['deactivatable'] = key.status == auth.Statuses.ACTIVE
    if key.owner != remote_user.user:
        raise Forbidden('You are not authorized to edit that key.')

    if key.status not in (auth.Statuses.ACTIVE, auth.Statuses.INACTIVE):
        raise Forbidden('Key not editable')

    if formdata.get('edit_key_submit', None) is not None:
        update_vals = formdata.to_dict()
        if formdata.get('deactivate', 'no') == 'yes':
            update_vals['status'] = auth.Statuses.INACTIVE
        else:
            update_vals['status'] = key.status
        auth.update_db_object(key,
                              ('description', 'email', 'status'),
                              update_vals)
        return flask.redirect(flask.url_for('user_root'))
    return flask.render_template('edit_key.html', **tmplargs);


@app.route('/', methods=['GET', 'POST'])
@authenticated_route
@extract_formdata(required=('email', 'description'))
def user_root(remote_user=None, formdata={}, **kwargs):
    tmplargs={'is_admin': False}
    keys = remote_user.user.keys
    if flask.request.method == 'POST':
        tmplargs['formdata'] = formdata
        pending = len(filter(lambda x: x.status == auth.Statuses.PENDING,
                             keys))
        if pending >= 2:
            tmplargs['form_error'] = "You have 2 pending keys.  Please wait until they are approved before requesting more."
        else:
            try:
                auth.add_key(remote_user.user,
                             email=formdata['email'],
                             description=formdata['description'])
                del tmplargs['formdata']
            except ValidationError as e:
                tmplargs['field_error'] = e.field
                tmplargs['form_error'] = e
    # Sort in descending order by mod date
    tmplargs['all_keys'] = sorted(keys, key=lambda x: x.modified, reverse=True)
    tmplargs['remote_user'] = remote_user
    return flask.render_template('request.html', **tmplargs)

