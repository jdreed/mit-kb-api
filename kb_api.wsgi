# -*- mode: python -*-

from werkzeug.wsgi import DispatcherMiddleware
from kb_api.server import app as apiserver
from kb_api.admin import app as adminserver
import pprint

# Apache must be able to write here
# (including the correct SELinux context
logfile = '/var/www/kb_api/logs/wsgi.log'

class LoggingMiddleware:

    def __init__(self, application):
        self.__application = application

    def __call__(self, environ, start_response):
        with open(logfile, 'a') as f:
            pprint.pprint(('REQUEST', environ), stream=f)

        def _start_response(status, headers, *args):
            with open(logfile, 'a') as f:
                pprint.pprint(('RESPONSE', status, headers), stream=f)
            return start_response(status, headers, *args)

        return self.__application(environ, _start_response)

# Use a dispatcher to run both the admin and the API
# in the same WSGI environment
dispatcher = DispatcherMiddleware(apiserver,
	    { '/keys': adminserver })

#application = LoggingMiddleware(dispatcher)
application=dispatcher
