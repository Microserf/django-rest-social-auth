from django.conf.urls import url
from social.utils import setting_name

from . import views,


extra = getattr(settings, setting_name('TRAILING_SLASH'), True) and '/' or ''

urlpatterns = (
    # returns jwt only
    url(r'^social/jwt/(?P<provider>[^/]+){0}$'.format(extra),
        views.SocialJWTOnlyAuthView.as_view(),
        name='login_social_jwt'),

    # returns jwt + user_data
    url(r'^social/jwt_user/(?P<provider>[^/]+){0}$'.format(extra),
        views.SocialJWTUserAuthView.as_view(),
        name='login_social_jwt_user'),
    )
