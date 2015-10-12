__author__ = 'gomes'

from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.LoginRequestView.as_view(), name="home"),
    url(r'^login/$', views.LoginRequestView.as_view(), name="login"),
    url(r'^logout/$', views.LogoutRequestView.as_view(), name="logout"),
    url(r'^register/$', views.RegisterRequestView.as_view(), name="register"),
    url(r'^register/confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$', views.RegisterConfirmRequest.as_view(),
        name='register_confirm'),
    url(r'^reset/password/$', views.PasswordResetRequestView.as_view(), name="reset_password"),
    url(r'^reset/password/confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$', views.PasswordResetConfirmView.as_view(),
        name='reset_password_confirm'),
]
