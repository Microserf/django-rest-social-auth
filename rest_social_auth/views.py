import logging
import warnings
try:
    from urlparse import urlparse
except ImportError:
    # python 3
    from urllib.parse import urlparse

from django.conf import settings
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.utils.encoding import iri_to_uri
from django.utils.six.moves.urllib.parse import urljoin
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from requests.exceptions import HTTPError
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from social.apps.django_app.utils import psa, STORAGE
from social.apps.django_app.views import _do_login as social_auth_login
from social.backends.oauth import BaseOAuth1
from social.exceptions import AuthException
from social.strategies.utils import get_strategy
from social.utils import partial_pipeline_data, user_is_authenticated, parse_qs

from .serializers import OAuth2InputSerializer, OAuth1InputSerializer, UserSerializer, TokenSerializer, UserTokenSerializer, JWTSerializer, UserJWTSerializer


l = logging.getLogger(__name__)


DOMAIN_FROM_ORIGIN = getattr(settings, 'REST_SOCIAL_DOMAIN_FROM_ORIGIN', True)
REDIRECT_URI = getattr(settings, 'REST_SOCIAL_OAUTH_REDIRECT_URI', '/')
STRATEGY = getattr(settings, 'REST_SOCIAL_STRATEGY', 'rest_social_auth.strategy.DRFStrategy')


def load_strategy(request=None):
    return get_strategy(STRATEGY, STORAGE, request)


class BaseSocialAuthView(GenericAPIView):
    """
    View will login or signin (create) the user from social oauth2.0 provider.

    **Input** (default serializer_class_in):

        {
            "provider": "facebook",
            "code": "AQBPBBTjbdnehj51"
        }

    + optional

        "redirect_uri": "/relative/or/absolute/redirect/uri"

    **Output**:

    user data in serializer_class format
    """

    oauth1_serializer_class_in = OAuth1InputSerializer
    oauth2_serializer_class_in = OAuth2InputSerializer
    serializer_class = None
    permission_classes = (AllowAny, )

    def disable_state_verification(self):
        # Disable the checking of state by setting the following params to False.
        # It is responsibility of the front-end to check state.
        # TODO: maybe create an additional resource, where front-end will
        # store the state before making a call to oauth provider
        # so server can save it in session and consequently check it before
        # sending request to acquire access token.
        # In case of token authentication we need a way to store an anonymous
        # session to do it.
        self.backend.REDIRECT_STATE = False
        self.backend.STATE_PARAMETER = False

    def do_login(self, backend, user):
        """
        Do login action here.
        For example in case of session authentication store the session in
        cookies.
        """

    def finalize_response(self, request, response, *args, **kwargs):
        try:
            self.strategy.finalize_response(response)
        except AttributeError:
            pass
        return super(BaseSocialAuthView, self).finalize_response(request, response, *args, **kwargs)

    def get_backend_name(self, request, *args, **kwargs):
        input_data = request.data
        if 'provider' in input_data:
            return input_data['provider']
        else:
            return kwargs.pop('provider')

    def get_object(self):
        is_authenticated = user_is_authenticated(self.request.user)
        user = is_authenticated and user or None

        partial = partial_pipeline_data(self.backend, user, *self.args, **self.kwargs)
        if partial:
            xargs, xkwargs = partial
            user = self.backend.continue_pipeline(*xargs, **xkwargs)

        else:
            if self.oauth_v1() and self.backend.OAUTH_TOKEN_PARAMETER_NAME not in input_data:
                # oauth1 first stage (1st is get request_token, 2nd is get access_token)
                request_token = parse_qs(self.backend.set_unauthorized_token())
                return Response(request_token)

            data = self.strategy.request_data()
            serializer_in = self.get_serializer_in(data=data)
            serializer_in.is_valid(raise_exception=True)
            user = self.backend.complete(user=user, *self.args, **self.kwargs)

        return user

    def get_redirect_uri(self, manual_redirect_uri):
        if not manual_redirect_uri:
            manual_redirect_uri = getattr(settings,
                'REST_SOCIAL_OAUTH_ABSOLUTE_REDIRECT_URI', None)
        return manual_redirect_uri

    def get_serializer_class_in(self):
        return self.oauth1_serializer_class_in if self.oauth_v1() else self.oauth2_serializer_class_in

    def get_serializer_in(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = self.get_serializer_class_in()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def initial(self, request, *args, **kwargs):
        super(BaseSocialAuthView, self).initial(request, *args, **kwargs)

        # Augment the request object by calling the decorator on a dummy function
        dummy = lambda r, b: None
        backend = self.get_backend_name(request, *args, **kwargs)
        psa(REDIRECT_URI, load_strategy=load_strategy)(dummy)(request, backend)

        self.backend = request.backend
        self.strategy = self.backend.strategy

        # Make sure social plays well with rest-social-auth
        self.disable_state_verification()
        self.set_backend_redirect_uri()

    def log_exception(self, error):
        err_msg = error.args[0] if error.args else ''
        if getattr(error, 'response', None) is not None:
            try:
                err_data = error.response.json()
            except (ValueError, AttributeError):
                l.error(u'%s; %s', error, err_msg)
            else:
                l.error(u'%s; %s; %s', error, err_msg, err_data)
        else:
            l.exception(u'%s; %s', error, err_msg)

    def oauth_v1(self):
        return isinstance(self.request.backend, BaseOAuth1)

    @method_decorator(never_cache)
    def post(self, request, *args, **kwargs):
        try:
            user = self.get_object()
        except (AuthException, HTTPError) as e:
            return self.respond_error(e)

        if isinstance(user, HttpResponse):  # An error happened and pipeline returned HttpResponse instead of user
            return user

        self.do_login(self.backend, user)

        serializer = self.get_serializer(instance=user)
        return Response(serializer.data)

    def respond_error(self, error):
        if isinstance(error, Exception):
            self.log_exception(error)
        else:
            l.error(error)
        return Response(status=status.HTTP_400_BAD_REQUEST)

    def set_backend_redirect_uri(self):
        manual_redirect_uri = self.strategy.request_data().pop('redirect_uri', None)
        manual_redirect_uri = self.get_redirect_uri(manual_redirect_uri)
        if manual_redirect_uri:
            self.backend.redirect_uri = manual_redirect_uri

        elif DOMAIN_FROM_ORIGIN:
            origin = self.request.META.get('HTTP_ORIGIN')
            if origin:
                relative_path = urlparse(self.backend.redirect_uri).path
                url = urlparse(origin)
                origin_scheme_host = "%s://%s" % (url.scheme, url.netloc)
                location = urljoin(origin_scheme_host, relative_path)
                self.backend.redirect_uri = iri_to_uri(location)



# Session authentication

class SocialSessionAuthView(BaseSocialAuthView):
    serializer_class = UserSerializer

    def do_login(self, backend, user):
        social_auth_login(backend, user, user.social_user)

    @method_decorator(csrf_protect)  # just to be sure csrf is not disabled
    def post(self, request, *args, **kwargs):
        return super(SocialSessionAuthView, self).post(request, *args, **kwargs)



# Token views

class SocialTokenOnlyAuthView(BaseSocialAuthView):
    serializer_class = TokenSerializer
    authentication_classes = (TokenAuthentication, )


class SocialTokenUserAuthView(BaseSocialAuthView):
    serializer_class = UserTokenSerializer
    authentication_classes = (TokenAuthentication, )



# JWT views

class JWTAuthMixin(object):
    def get_authenticators(self):
        try:
            from rest_framework_jwt.authentication import JSONWebTokenAuthentication
        except ImportError:
            warnings.warn('djangorestframework-jwt must be installed for JWT authentication',
                          ImportWarning)
            raise

        return [JSONWebTokenAuthentication()]


class SocialJWTOnlyAuthView(JWTAuthMixin, BaseSocialAuthView):
    serializer_class = JWTSerializer


class SocialJWTUserAuthView(JWTAuthMixin, BaseSocialAuthView):
    serializer_class = UserJWTSerializer
