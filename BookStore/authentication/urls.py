from django.urls import path
from .views import RegisterView, VerifyEmail, LoginAPIView, ResetPassword, NewPassword

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('email_verify/', VerifyEmail.as_view(), name='email_verify'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('reset_password/', ResetPassword.as_view(), name='reset_password'),
    path('new_password/', NewPassword.as_view(), name='new-password'),
]
