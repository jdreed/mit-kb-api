import io
import logging
import os.path

from ConfigParser import SafeConfigParser

logger = logging.getLogger('kb_api.config')

# Map of sections and options that must be present
CONFIG_REQUIRED = {'Connection': ['host', 'username', 'password'],
                   'API': ['prefix'],
                   'Authentication': ['db_uri'],
                   }
# Where to look for the config file
CONFIG_FILE_DEFAULTS=['/var/www/kb_api/conf/kb-api.ini',
                      os.path.join(os.getcwd(), 'kb-api.ini')]

CONFIG_DEFAULTS="""
[Text]
deleted_article=This article has been deleted.
not_authenticated=You did not supply an access token.
"""

class _APIConfig(SafeConfigParser):
    def __init__(self, config_file=None):
        SafeConfigParser.__init__(self)
        logger.debug("Parsing default text")
        self.readfp(io.BytesIO(CONFIG_DEFAULTS))
        logger.debug('Reading default config files: %s', CONFIG_FILE_DEFAULTS)
        config_read = self.read(CONFIG_FILE_DEFAULTS)
        if config_file is not None:
            logger.debug('Reading from specified config file: %s', config_file)
            config_read += self.read(config_file)
        logger.debug('Read from files: %s', config_read)
        if len(config_read) == 0:
            raise ValueError('Could not find any config file to use.')
        # Validate the config now, not when we need stuff from it
        for section in CONFIG_REQUIRED:
            for option in CONFIG_REQUIRED[section]:
                if not self.has_option(section, option):
                    err = "config file: missing option '{0}' in section '{1}'"
                    err = err.format(section, option)
                    logger.error(err)
                    raise ValueError(err)

    @property
    def default_permissions(self):
        if not self.has_section('DefaultPermissions'):
            return {}
        return dict(self.items('DefaultPermissions'))

    @property
    def anonymous_permissions(self):
        if not self.has_section('AnonymousPermissions'):
            return {}
        return dict(self.items('AnonymousPermissions'))

APIConfig = _APIConfig()
