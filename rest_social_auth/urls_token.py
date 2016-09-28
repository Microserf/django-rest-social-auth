from django.conf.urls import url
from social.utils import setting_name

from .views import SocialTokenOnlyAuthView, SocialTokenUserAuthView,


extra = getattr(settings, setting_name('TRAILING_SLASH'), True) and '/' or ''

urlpatterns = (
    # returns token only
    url(r'^login/(?P<provider>[^/]+){0}$'.format(extra),
        SocialTokenOnlyAuthView.as_view(),
        name='login_social_token'),

    # returns token + user_data
    url(r'^login/(?P<provider>[^/]+){0}$'.format(extra),
        SocialTokenUserAuthView.as_view(),
        name='login_social_token_user'),
)
