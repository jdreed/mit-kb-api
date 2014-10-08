import logging
from flask.ext.sqlalchemy import SQLAlchemy

# Import these from sqlalchemy itself, because you can't reference
# these via SQLAlchemy() until there's a request or app context
from sqlalchemy import event, engine

from .config import APIConfig

db = SQLAlchemy()
logger = logging.getLogger('kb_api.database')

@event.listens_for(engine.Engine, "connect")
def on_db_connect(dbapi_connection, connection_record):
    drivername = db.engine.url.drivername
    logger.debug("on_db_connect: url=%s", db.engine.url)
    # Enable foreign keys for SQLite
    if drivername.startswith('sqlite'):
        logger.info("Enabling foreign keys for SQLite")
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# If we wanted to not use flask.ext.sqlalchemy, we'd need something like this:
#
# from sqlalchemy import create_engine
# from sqlalchemy.orm import scoped_session, sessionmaker
# from sqlalchemy.ext import declarative
#
# engine = sqlalchemy.create_engine(URI_GOES_HERE)
# db_session = scoped_session(sessionmaker(bind=engine))
#
# the Base class for the ORM, then imported into models.py
# Base = declarative.declarative_base()
# Base.query = db_session.query_property()
#
# However, when initializing the db, you need to do "from . import models"
# (or some such) and then Base.metadata.create_all(bind=engine)

