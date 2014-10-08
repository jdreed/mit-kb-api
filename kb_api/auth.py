import logging
import re
import uuid

from flask import g
from sqlalchemy import desc
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from werkzeug.local import LocalProxy

from . import models
from .config import APIConfig
from .database import db

logger = logging.getLogger('kb_api.auth')

class AuthenticationError(Exception):
    pass

class DatabaseError(Exception):
    pass

class MalformedTokenError(Exception):
    pass

class InvalidTokenError(Exception):
    pass

class Permissions:
    """
    An enum of permissions
    """
    NONE = 0x00
    READ = 0x01
    WRITE = 0x02
    WRITELABELS = 0x04

class Token:
    _re = re.compile(r'bearer ([\w\-]+)$')
    authenticated = True

    def __init__(self, token):
        self.key = lookup_key(token)
        if self.key is None:
            raise InvalidTokenError

    def __repr__(self):
        return "{0}({1})".format(self.__class__.__name__, self.key)

    def __getattr__(self, name):
        return getattr(self.key, name)

    @classmethod
    def extract(cls, tokenstr):
        """Extract a token, or raise a malformed token error"""
        if not isinstance(tokenstr, basestring):
            raise ValueError("Token.extract requires a string")
        logger.debug('Attempting to extract token from: %s', tokenstr)
        match = Token._re.match(tokenstr)
        if match is not None:
            return cls(match.group(1))
        raise MalformedTokenError

    @staticmethod
    def generate():
        return str(uuid.uuid4())

class AnonymousToken:
    authenticated = False
    status = None
    permissions = {}

    def __init__(self):
        self.permissions = AnonymousPermissions

    def can(self, op, space):
        return space in self.permissions and \
            (self.permissions[space] & op) != 0

    def __repr__(self):
        return "AnonymousToken({0})".format(self.permissions)


class PermissionSet:
    """Something which acts like a models.Permission collection, but isn't"""
    def __init__(self, permissions):
        logger.debug("init permissions proxy with %s", permissions)
        self.permissions = {}
        for k,v in permissions.items():
            try:
                self.permissions[k] = getattr(Permissions, v)
            except AttributeError as e:
                raise ValueError("Invalid permission '{0}' for space '{1}'".format(v,k))

    def __contains__(self, item):
        return item in self.permissions

    def __len__(self):
        return len(self.permissions)
    
    def __getitem__(self, key):
        return self.permissions[key]

    def __iter__(self):
        return iter(self.permissions)

    def __repr__(self):
        return "{0}({1})".format(self.__class__.__name__,
                                 repr(self.permissions) if len(self.permissions) else "none")

class _Statuses:
    """Hack for treating this like a dynamic ENUM"""
    _all = ('ACTIVE', 'REVOKED', 'INACTIVE', 'RESERVED', 'PENDING')

    def __init__(self):
        try:
            self._statuses = models.Status.query.all()
        except ProgrammingError as e:
            logger.error(e)
            raise DatabaseError("Statuses could not be loaded from database")
        if len(self._statuses) < 1:
            raise DatabaseError("No statuses in database")
        self._status_dict = {s.value: s for s in self._statuses}

    def __getattr__(self, attr):
        if attr not in self._status_dict:
            if attr in _all:
                raise DatabaseError('Status {0} not in database'.format(attr))
        return self._status_dict[attr]

    def __contains__(self, item):
        if isinstance(item, models.Status):
            return item in self._statuses
        elif isinstance(item, basestring):
            return item in self._status_dict
        raise TypeError("Cannot test '{0}' for membership in Statuses".format(
            item.__class__.__name__))

    @property
    def all(self):
        return self._statuses

    @classmethod
    def get_models(cls):
        return [models.Status(value=x) for x in cls._all]

class RemoteUser(object):
    def __init__(self, **kwargs):
        lookup_by = kwargs.pop('lookup_by', 'username')
        nolookup = kwargs.pop('no_lookup', False)
        self._attrs = kwargs
        self.user = None
        if not nolookup:
            if lookup_by not in kwargs:
                raise ValueError("Can't lookup user by '{0}': not in kwargs".format(lookup_by))
            self.user = lookup_user(kwargs[lookup_by], lookup_by)
        logger.debug("init remote user with %s", kwargs)
            
    @property
    def authenticated(self):
        return self.user is not None

    @property
    def is_administrator(self):
        return self.authenticated and self.user.is_admin

    def __getattr__(self, name):
        if self.user is not None:
            return getattr(self.user, name)
        else:
            return self._attrs[name]

    def __repr__(self):
        return "RemoteUser({0})".format(self.user)

    def __str__(self):
        if not self.authenticated:
            return "(not logged in)"
        if self.real_name is not None:
            return "{0} ({1})".format(self.real_name, self.username)
        return self.username

    @staticmethod
    def strip_domain(email_addr):
        return email_addr.split('@', 1)[0]

class X509RemoteUser(RemoteUser):
    def __init__(self, environ, **kwargs):
        try:
            vals = { 'username': environ['SSL_CLIENT_S_DN_Email'].lower(),
                     'real_name' :environ['SSL_CLIENT_S_DN_CN'],
                     'email': environ['SSL_CLIENT_S_DN_Email'].lower() }
            kwargs.update(vals)
        except KeyError:
            logger.exception("Bad x509 data")
            raise AuthenticationError("Unable to parse X.509 certificate data in environment")
        super(X509RemoteUser, self).__init__(**kwargs)


def _load_statuses():
    statuses = getattr(g, '_auth_statuses', None)
    if statuses is None:
        logger.debug("Creating global statuses instance")
        statuses = g._auth_statuses = _Statuses()
    return statuses

# A proxy object which won't resolve references until inside the
# app context with the db loaded
Statuses = LocalProxy(_load_statuses)
DefaultPermissions = PermissionSet(APIConfig.default_permissions)
AnonymousPermissions = PermissionSet(APIConfig.anonymous_permissions)

# A bunch of database convenience functions.  These don't have to live
# here, but keeping these abstracts ensures that the views don't
# have to worry about commiting the database state.

def _db_select_one(queryobj):
    """Thin wrapper around .one() generating the exceptions we want"""
    data = None
    try:
        data = queryobj.one()
    except NoResultFound:
        logger.debug("Query returned 0 results")
    except MultipleResultsFound as e:
        logger.warn("Query returned multiple results", exc_info=1)
        raise DatabaseError("The database is corrupt.")
    except ProgrammingError as e:
        raise DatabaseError("The query failed.   Has the database been created?")
    return data

def create_tables():
    """Create the database tables."""
    db.drop_all()
    db.create_all()
    logger.info("Populating 'status' table")
    for status in _Statuses.get_models():
        logger.debug("Adding status %s", status)
        db.session.add(status)
    db.session.commit()

def update_db_object(obj, fields, values):
    """Update an object in the database, but only if its attributes have changed.

    While SQLAlchemy keeps track of dirty attributes, it does not
    track changes.  e.g. if Thing.foo is 'bar' and you set
    Thing.foo='bar', it will get marked as dirty and committed, thus
    triggering a modtime change.
    """
    changed=False
    for key in fields:
        if getattr(obj, key) != values[key]:
            changed=True
            setattr(obj, key, values[key])
    if changed:
        db.session.commit()

def add_key(owner, **kwargs):
    key = owner.add_key(status_id=Statuses.ACTIVE.id if kwargs.pop('auto_approve', False) else Statuses.PENDING.id,
                  key=Token.generate(), **kwargs)
    for space in DefaultPermissions:
        key.set_permission(space, DefaultPermissions[space])
    db.session.commit()
    return key

def get_all_keys():
    return models.Key.query.order_by(models.Key.modified.desc()).all()

def lookup_key(key):
    return _db_select_one(models.Key.query.filter(models.Key.key == key))

def lookup_user(criterion, by='username'):
    if by == 'username':
        query_filter = models.User.username == criterion
    elif by == 'key':
        query_filter = models.User.keys.any(key=criterion)
    else:
        raise ValueError("Don't know how to look up user by '{0}'".format(by))
    return _db_select_one(models.User.query.filter(query_filter))

def add_user(username=None, **kwargs):
    if username is None:
        raise ValueError("{0}.add_user: username not optional".format(__name__))
    vals = {
        'username': username,
        'email': kwargs.get('email', username if '@' in username else None),
        'real_name': kwargs.get('real_name', "User {0}".format(username)),
        'is_admin': kwargs.get('is_admin', False)
    }
    user = models.User(**vals)
    logger.debug("Adding user: %s", user)
    db.session.add(user)
    db.session.commit()
    return user

