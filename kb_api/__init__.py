import logging

logging.basicConfig()

# Set up logging here

from .config import APIConfig as config

log_level = config.get('Logging', 'level', 'WARNING')
log_file = config.get('Logging', 'file', None)
logsql = False
try:
    logsql = str(config.get('Logging', 'log_sql', 'no')).lower() == 'yes'
except ValueError as e:
    logging.error("Invalid value for log_sql in config file")
if log_file is not None:
    try:
        hdlr = logging.FileHandler(log_file)
        hdlr.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(message)s'))
        logging.getLogger('kb_api').addHandler(hdlr)
        if logsql:
            logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
            logging.getLogger('sqlalchemy.engine').addHandler(hdlr)
    except IOError as e:
        logging.getLogger('kb_api').warning("Warning: Cannot log to file: {0}".format(e))
    logging.getLogger('kb_api').setLevel(getattr(logging, log_level))
