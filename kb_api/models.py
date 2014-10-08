#import sqlalchemy as sql
import sys
from .database import db
from datetime import datetime
#from sqlalchemy.orm import validates
import logging

logger = logging.getLogger('kb_api.models')
Base=db.Model
validates = db.validates
sql=db
sql.orm=db

class ValidationError(Exception):
    def __init__(self, field, error):
        self.field = field
        self.error = error
        super(ValidationError, self).__init__(error)

    def __repr__(self):
        return "ValidationError({0}, {1:.10})".format(self.field, self.error)

    def __str__(self):
        return "'{0}': {1}".format(self.field, self.error)
    

class Validations:
    """
    A class of validations to apply to columns
    The docstrings of the functions are the human readable
    error messages.
    """

    @staticmethod
    def nonempty_string(thing):
        """a non-empty string is required"""
        return isinstance(thing, basestring) and len(thing.strip()) > 0

class ModelError(Exception):
    pass

class Permission(Base):
    """The representation of a single permission in the DB"""
    __tablename__ = "permissions"
    
    key_id = sql.Column(sql.Integer, sql.ForeignKey("keys.id"))
    space_key = sql.Column(sql.String(64))
    permissions = sql.Column(sql.Integer)

    __table_args__ = (sql.PrimaryKeyConstraint(key_id, space_key),)

    def __repr__(self):
        return "Permission({0}={1})".format(self.space_key, self.permissions)

class Status(Base):
    """Lookup table for statuses"""
    __tablename__ = 'status'

    id = sql.Column(sql.Integer, sql.Sequence('status_id_seq'), primary_key=True)
    value = sql.Column(sql.String(32), unique=True)

    def __eq__(self, other):
        return other.id == self.id

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "Status({0},{1})".format(self.id, self.value)

    def __str__(self):
        return self.value


class User(Base):
    """Representation of a 'user' in the database"""
    __tablename__ = 'users'

    id = sql.Column(sql.Integer, sql.Sequence('user_id_seq'), primary_key=True)
    username = sql.Column(sql.String(50), nullable=False,
                          unique=True, index=True)
    email = sql.Column(sql.String(255), nullable=False)
    real_name = sql.Column(sql.String(255), nullable=False)
    is_admin = sql.Column(sql.Boolean(), nullable=False)

    keys = sql.orm.relationship("Key")

    def __repr__(self):
        return "User({0}, {1})".format(self.id, self.username)

    def __str__(self):
        return self.username

    def add_key(self, **kwargs):
        kwargs['owner_id'] = self.id
        if 'email' not in kwargs:
            kwargs['email'] = self.email
        key = Key(**kwargs)
        logger.debug("Adding key %s for %s", key, self)
        self.keys.append(key)
        return key

    @validates('username', 'email')
    def require_nonempty(self, key, val):
        logger.debug("Validating '%s' as '%s'", key, val)
        if not isinstance(val, basestring) or len(val.strip()) < 1:
            raise ValidationError(key, "a non-empty string is required")
        return val

class Key(Base):
    """Representation of a 'user' in the database"""
    __tablename__ = 'keys'

    id = sql.Column(sql.Integer, sql.Sequence('key_id_seq'), primary_key=True)
    key = sql.Column(sql.String(36), nullable=False,
                     index=True, unique=True)
    owner_id = sql.Column(sql.Integer, sql.ForeignKey("users.id"), nullable=False)
    email = sql.Column(sql.String(50), nullable=False, info={'validate':Validations.nonempty_string})
    created = sql.Column(sql.DateTime(), nullable=False, default=datetime.now)
    modified = sql.Column(sql.DateTime(), nullable=False, default=datetime.now,
                          onupdate=datetime.now)
    description = sql.Column(sql.Text())
    status_id = sql.Column(sql.Integer, sql.ForeignKey("status.id"), nullable=False)

    permissions = sql.orm.relationship("Permission", backref="user")
    status = sql.orm.relationship("Status", uselist=False)
    owner = sql.orm.relationship("User", uselist=False)
    
    def __repr__(self):
        return "Key({0}, {1}, {2})".format(self.email,
                                           self.status,
                                           self.key)

    def _get_permission(self, space):
        perms = [x for x in self.permissions if x.space_key == space]
        if len(perms) > 1:
            raise ModelError("user %d has multiple perms %s".format(self.id,
                                                                    space))
        return perms[0] if len(perms) else None

    def can(self, op, space):
        perm = self._get_permission(space)
        logger.debug("perm=%s", perm)
        return False if perm is None else (op & perm.permissions != 0)

    def set_permission(self, space, *mode):
        perms = reduce(lambda x, y: x | y, mode)
        perm = self._get_permission(space)
        if perm is None:
            self.permissions.append(Permission(space_key=space, permissions=perms))
        else:
            perm.permissions = perms

    @validates('email')
    def require_nonempty(self, key, val):
        logger.debug("Validating '%s' as '%s'", key, val)
        if not isinstance(val, basestring) or len(val.strip()) < 1:
            raise ValidationError(key, "a non-empty string is required")
        return val


