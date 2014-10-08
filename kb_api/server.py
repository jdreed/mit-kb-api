import flask
import json
import logging
import sys
import xml.etree.ElementTree as xmletree
import html5lib

from flask.ext.restful import Api, Resource, reqparse, abort, fields, marshal
from werkzeug.exceptions import (HTTPException, Gone, InternalServerError,
                                 NotImplemented, NotFound, MethodNotAllowed,
                                 Forbidden, Unauthorized, NotAcceptable,
                                 BadRequest)

from confluence.shortcode import code2id
from confluence.rpc import Session, RemoteException
from xml.sax import saxutils

from .config import APIConfig as config
from .database import db
from . import auth

logger = logging.getLogger('kb_api.server')

confluence_session = Session(config.get('Connection', 'host'))
confluence_session.login(config.get('Connection', 'username'),
                         config.get('Connection', 'password'))

def html_escape(thing):
    if isinstance(thing, dict):
        return {k: html_escape(v) for k,v in thing.items()}
    if isinstance(thing, str):
        return saxutils.escape(thing)
    return thing

def require_access(user, op=None, space=None):
    logger.debug("require_access(%s, %s, %s)", user, op, space)
    logger.debug(user.permissions)
    if user.can(op, space):
        return True
    logger.debug("access denied")
    raise Forbidden(config.get('Text', 'forbidden'))

def cors_headers():
    # flask-restful's CORS support is wrong.  It does not correctly
    # handle the requesting Origin header, and modern FF/Chrome disallow
    # '*' when passing auth tokens
    headers = {}
    origin = flask.request.headers.get('Origin', '*')
    headers['Access-Control-Allow-Origin'] = origin
    # Per http://fetch.spec.whatwg.org/#http-access-control-allow-methods
    # this is what methods are allowed in the CORS protocol, and is orthogonal
    # to the Allow: header
    headers['Access-Control-Allow-Methods'] = 'HEAD, GET, POST, PUT, DELETE, PATCH, OPTIONS'
    headers['Access-Control-Max-Age'] = 21600
    headers['Access-Control-Allow-Headers'] = 'authorization, accept'
    return headers

def get_authentication(f):
    def auth_decorator(*args, **kwargs):
        auth_header = flask.request.headers.get('Authorization', None)
        if auth_header is None:
            token = auth.AnonymousToken()
        else:
            try:
                token = auth.Token.extract(auth_header)
            except auth.MalformedTokenError:
                raise BadRequest("Malformed token")
            except auth.InvalidTokenError:
                raise Unauthorized(config.get('Text', 'not_logged_in'))
        kwargs['_api_user'] = token
        logger.debug("Retrieved token: %s", kwargs['_api_user'])
        return f(*args, **kwargs)
    return auth_decorator

def require_authentication(f):
    def auth_decorator(*args, **kwargs):
        if '_api_user' not in kwargs:
            raise InternalServerError('require_authentication called before get_authentication')
        if not kwargs['_api_user'].authenticated:
            raise Unauthorized(config.get('Text', 'not_logged_in'))
        return f(*args, **kwargs)
    return auth_decorator


class ParsedException:
    """Parse an exception for formatting later"""
    _html_template="""
<html>
<head><title>API Error: Code {code}</title></head>
<body><h1>{code} {error_type}</h1>
<p>Sorry, the following error occurred: <strong>{error}</strong><br/>
<em>Lo sientamos.  Ha ocurrido el siguiente error: {error}</em></p>
<p>Additional information: {description}</p>
</body>
</html>
"""

    def __init__(self, e):
        self.error = e.message
        self.error_type = e.__class__.__name__
        logger.debug('Parsing exception of type %s: %s', self.error_type,
                     e)
        self.code = 500
        self.description = "Unexpected exception, please report this bug."
        if isinstance(e, HTTPException):
            logger.debug('Exception is HTTPException or subclass')
            # This is wrapped here in case there's some other Exception
            # type that happens to have a 'code' attribute
            self.code = getattr(e, 'code', self.code)
            self.description = getattr(e, 'description', None)
            if self.code == 405:
                self.valid_methods = e.valid_methods
                if self.description is None:
                    self.description = ''
                self.description += " (valid HTTP methods: {0})".format(e.valid_methods)
        else:
            logger.exception(e)

    @property
    def json(self):
        return {k: v for k,v in self.__dict__.items() if not k.startswith('_')}
    
    @property
    def html(self):
        return self._html_template.format(**html_escape(self.__dict__))

class APISyntaxError(BadRequest):
    """An API syntax error

    This is a subclass of BadRequest, because we want to differentiate
    between HTTP errors (which we raise) and other Exceptions (which
    we're not expecting, and thus should be 500 errors
    """
    pass

class KBAPI(Api):
    def __init__(self, *args, **kwargs):
        # Set the default mediatype to nothing so that the
        # Accept: header is actually honored correctly (see below)
        kwargs['default_mediatype'] = ''
        # Catch all 404 errors so that the CORS headers get added
        kwargs['catch_all_404s'] = True
        super(KBAPI, self).__init__(*args, **kwargs)
        self.representations = {
            'application/json': self.json,
            'text/html': self.html,
            }

    def mediatypes(self):
        # If it can accept JSON, but doesn't explicitly do so (that is, they
        # have not specified a ranking), given it JSON
        mtypes = super(KBAPI, self).mediatypes()
        logger.debug('Request wants media types: %s', mtypes)
        if flask.request.accept_mimetypes.accept_json and 'application/json' not in mtypes:
            logger.debug('Adding application/json to mediatypes')
            mtypes.insert(0, 'application/json')
        return mtypes

    def make_response(self, data, *args, **kwargs):
        # Actually honor the Accept: header.  Otherwise it
        # returns None and throws a Flask error
        logger.debug("Returning data: %s", repr(data)[:80])
        rv = super(KBAPI, self).make_response(data, *args, **kwargs)
        if rv is None:
            logger.debug("make_response returned None")
            rv = flask.make_response(NotAcceptable(), 406)
        rv.headers.extend(cors_headers())
        return rv

    def handle_error(self, e):
        if not flask.request.path.startswith(self.prefix):
            return flask.make_response(e)
        request=flask.request
        print >>sys.stderr, request.path, request.base_url, request.url, request.url_root
        parsed = ParsedException(e)
        rv = parsed.json
        rv['html'] = parsed.html
        return self.make_response(rv, parsed.code)

    def html(self, data, code, headers=None):
        if isinstance(data, dict) and 'html' in data:
            resp = flask.make_response(data['html'], code)
            resp.headers.extend(headers or {})
            return resp
        logger.debug("html() was asked to format something without html")
        raise NotAcceptable()

    def json(self, data, code, headers=None):
        if not isinstance(data, dict):
            raise InternalServerError('KBAPI.json() received data that was not a dictionary.')
        resp = flask.make_response(json.dumps(data, indent=2) + "\n", code)
        resp.headers.extend(headers or {})
        return resp

class KBResource(Resource):
    """Base Resource class for module that logs things"""

    method_decorators = [get_authentication]

    def dispatch_request(self, *args, **kwargs):
        logger.info("%s.%s(%s)", self.__class__.__name__,
                    flask.request.method.lower(), kwargs)
        return super(KBResource, self).dispatch_request(*args, **kwargs)

    # This is essentially a no-op, but is required for the CORS support
    # decorator.  Otherwise, flask would return a 405 before the wrapper
    # gets invoked.
    def options(self, **kwargs):
        # Fake an options response in 3 parts.  We could use the default
        # options response, but then it wouldn't go through make_response,
        # and I only want to add the CORS headers in one place.  I don't think
        # there's a real performance hit there.
        return {}, 200, {'Allow': ', '.join(['HEAD'] + self.methods)}

class AuthenticatedResource(KBResource):
    # Remember, these are applied in the reverse order
    method_decorators = [require_authentication, get_authentication]

class Base(KBResource):
    """The root level of the API."""
    def get(self, **kwargs):
        txt = config.get('API', 'root_text', 'How about a nice game of chess?')
        docs = config.get('API', 'doc_url', 'http://example.com')
        html = """
<html><head><title>{title}</title></head>
<body><h1>{title}</h1>
<p>Documentation is available at <a href="{uri}">{uri}</a>.</p></body>
</html>"""
        return {'text': txt,
                'documentation': docs,
                'html': html.format(title=html_escape(txt), uri=docs)}

class Test(AuthenticatedResource):
    """Test the API."""
    def get(self, **kwargs):
        text = 'Hello, world!'
        return { 'text': text,
                 'html': '<html><head><title>{title}</title></head><body><h1>{text}</h1><p>{text}</p></body></html>'.format(title=text, text=text) }

#        txt = "foo"
#        docs = "bar"
#        return {'text': txt,
#                'documentation': docs}

class Shortcode(AuthenticatedResource):
    """Convert a shortcode to a page id."""
    def get(self, code, **kwargs):
        rv = {'id': code2id(code)}
        # Don't marshal the dictionary itself because we don't want to
        # clobber the 'id'
        rv.update(marshal(rv, {'rest_uri': fields.Url('article')}))
        return rv

class LabelArticles(AuthenticatedResource):
    def get(self, **kwargs):
        user = kwargs.get('_api_user')
        require_access(user)
        if 'id' in kwargs:
            articles = confluence_session.getLabelContentById(kwargs.get('id'))
        else:
            articles = confluence_session.getLabelContentByName(kwargs.get('name'))
        # Filter out non-pages
        articles = [x for x in articles if x.type == 'page']
        return {'articles': [marshal(x, {k:v for k,v in Article._fields.items() if k in ('url', 'type', 'id', 'title', 'rest_uri')}) for x in articles]}

class Labels(AuthenticatedResource):
    _fields = {
        'name': fields.String,
        'id': fields.Integer,
        'rest_uri': fields.Url('label')
        }

    def get(self, **kwargs):
        user = kwargs.get('_api_user')
        require_access(user)
        label_name = kwargs.get('name')
        labels = confluence_session.getLabelsByDetail(label_name=label_name)
        if len(labels) == 0:
            raise NotFound('No labels found matching that name.')
        return {'labels': [marshal(x, Labels._fields) for x in labels]}

class ArticleLabels(AuthenticatedResource):
    def __init__(self, *args, **kwargs):
        super(ArticleLabels, self).__init__(*args, **kwargs)
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('name', type=str)

    def get(self, **kwargs):
        user = kwargs.get('_api_user')
        page = confluence_session.getPageById(kwargs.get('id'))
        require_access(user, auth.Permissions.READ, page.space)
        labels = confluence_session.getLabelsById(page.id)
        if 'name' in kwargs:
            labels = [x for x in labels if x.name == kwargs.get('name')]
            if len(labels) == 0:
                raise NotFound('No label {0} for article id {1}'.format(
                        kwargs.get('name'), kwargs.get('id')))
        return {'labels': [marshal(x, Labels._fields) for x in labels] }

    def put(self, **kwargs):
        if 'name' not in kwargs:
            raise MethodNotAllowed(valid_methods=['GET', 'POST'])
        return self._validate_and_add_label(**kwargs), 201

    def delete(self, **kwargs):
        raise NotImplemented('Not yet implemented')

    def post(self, **kwargs):
        args = self.parser.parse_args()
        name = args['name']
        if name is None:
            # I don't like flask-restful's handling of required arguments,
            # and it doesn't play nice with the custom error handler anyway
            raise APISyntaxError("'name' is required in POST data")
        return self._validate_and_add_label(name=name, **kwargs)

    def _validate_and_add_label(self, **kwargs):
        user = kwargs.get('_api_user')
        name = kwargs.get('name')
        id = kwargs.get('id')
        try:
            page = confluence_session.getPageById(id)
        except RemoteException:
            raise NotFound("Unable to retrieve a page with id: {0}".format(id))
        require_access(user, auth.Permissions.WRITE, page.space)
        if not confluence_session.addLabelByName(name, id):
            raise InternalServerError('Failed to add label.  No more info available.')
        rv = {'data': 'Label added',
              'id': kwargs.get('id'),
              'name': name}
        _fields = {'data': fields.String,
                   'rest_uri': fields.Url('article_labels')}
        return marshal(rv, _fields)

class ArticleCollection(AuthenticatedResource):
    def post(self, **kwargs):
        raise NotImplemented('Not yet implemented')

class Article(AuthenticatedResource):
    _fields = {
        'content': fields.String,
        'space': fields.String,
        'title': fields.String,
        'url': fields.String,
        'contentStatus': fields.String,
        'created': fields.DateTime,
        'modified': fields.DateTime,
        'short_url': fields.String,
        'id': fields.Integer,
        'rest_uri': fields.Url('article')
    }

    _valid_formats = ('div', 'html', 'object')
    _valid_parts = ('all', 'excerpt')

    def get(self, **kwargs):
        user = kwargs.get('_api_user')
        fmt = kwargs.get('format', 'object')
        part = kwargs.get('part', 'all')
        if fmt not in self._valid_formats:
            raise APISyntaxError("Unknown format: {0}".format(fmt))
        if part not in self._valid_parts:
            raise APISyntaxError("Unknown part: {0}".format(part))
        try:
            page = confluence_session.getPageById(kwargs.get('id'))
        except RemoteException:
            raise NotFound('Page not found')
        require_access(user, auth.Permissions.READ, page.space)
        logger.debug("Access checked")
        page.short_url = confluence_session.make_short_url(page.shortcode)
        if not page.current:
            raise Gone(config.get('Text', 'deleted_article',
                                  'Article deleted.'))
        # Make a copy so we don't clobber the class one
        marshal_fields = self._fields.copy()
        render_kwargs = {'page_id': page.id}
        if part == 'excerpt':
            if page.excerpt is None:
                raise NotFound('The article has no excerpt.')
            del marshal_fields['content']
            marshal_fields['excerpt'] = fields.String
            render_kwargs['content'] = page.excerpt
        # Why do we not simply always pass 'content' to renderContent,
        # and just decide between the page content or the excerpt?  Because
        # when a page is rendered by page_id alone, it can be (and is) cached.
        # when a page is rendered by arbitrary content, it is not.
        if fmt == 'html':
            return {'html': confluence_session.renderContent(**render_kwargs) }
        if fmt == 'div':
            html = confluence_session.renderContent(style='clean',
                                                    **render_kwargs)
            parsed = html5lib.parseFragment(html, treebuilder='etree',
                                            namespaceHTMLElements=False)
            for el in parsed.findall(".//img"):
                if el.get('src').startswith('/confluence'):
                    el.set('src', 'http://kb.mit.edu' + el.get('src'))
            for el in parsed.findall(".//a"):
                if el.get('href', '').startswith('/confluence'):
                    el.set('href', 'http://kb.mit.edu' + el.get('href'))
            cleaned = xmletree.tostring(parsed[0], method='html' )
            return {'html':  cleaned}
        return { 'page': marshal(page,
                                 marshal_fields)}

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

app = flask.Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.get('Authentication', 'db_uri')
db.init_app(app)
api = KBAPI(app, prefix=config.get('API', 'prefix', ''))
api.add_resource(Base, '/')
api.add_resource(Test, '/test')
api.add_resource(ArticleCollection, '/articles')
api.add_resource(Article,
                 '/articles/<int:id>',
                 '/articles/<int:id>/<string:format>',
                 '/articles/<int:id>/<string:format>/<string:part>',
                 endpoint='article')
api.add_resource(ArticleLabels,
                 '/articles/<int:id>/labels',
                 '/articles/<int:id>/labels/<string:name>',
                 endpoint='article_labels')
api.add_resource(Labels,
                 '/labels/<string:name>',
                 endpoint='label')
api.add_resource(LabelArticles,
                 '/labels/<int:id>/articles',
                 '/labels/<string:name>/articles',
                 endpoint='labels')
api.add_resource(Shortcode,
                 '/shortcode/<string:code>')
