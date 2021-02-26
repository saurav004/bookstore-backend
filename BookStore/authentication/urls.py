from django.urls import path
from .views import RegisterView, VerifyEmail, LoginAPIView, ResetPassword, NewPassword, ChangeUserPassword, LogoutUser

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('email_verify/', VerifyEmail.as_view(), name='email_verify'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('reset_password/', ResetPassword.as_view(), name='reset_password'),
    path('new_password/', NewPassword.as_view(), name='new_password'),
    path('change_password/', ChangeUserPassword.as_view(), name='change_password'),
    path('logout/', LogoutUser.as_view(), name='logout')
]
