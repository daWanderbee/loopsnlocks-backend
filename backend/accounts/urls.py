from django.urls import path
from . import views

urlpatterns = [
    path('signup/request-otp/', views.request_otp_signup, name='request_otp_signup'),
    path('signup/verify-otp/', views.verify_otp_and_register, name='verify_otp_signup'),
    path('login/', views.login_user, name='login_user'),
    path('login/request-otp/', views.request_otp_login, name='request_otp_login'),
    path('logout/', views.logout_view, name='logout'),
    path('check-username/', views.check_username, name='check_username'),
    path("whoami/", views.whoami, name="whoami"),
]