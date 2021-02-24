import jwt
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import generics, status
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer, ResetPasswordEmailSerializer, \
    NewPasswordSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .tasks import send_email


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    @csrf_exempt
    def post(self, request):
        """
        Objective: Register a new User
        :param request: Email, username, password, Mobile Number
        :return: user detail and success message
        """
        user = request.data
        serializer = self.serializer_class(data=user)
        if serializer.is_valid():
            serializer.save()
            user_data = serializer.data
            user = User.objects.get(email=user_data['email'])
            token = RefreshToken.for_user(user).access_token
            current_site = get_current_site(request).domain
            relative_link = reverse('email_verify')
            absurl = 'http://' + current_site + relative_link + "?token=" + str(token)
            email_body = 'Hi \n' + user.username + ' Use the link below to verify your email \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify you email'}
            send_email.delay(data)
            return Response({"message": "user created", "data": user_data}, status=status.HTTP_201_CREATED)
        return Response(
            {"status": status.HTTP_400_BAD_REQUEST, "message": None, "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST, )


class VerifyEmail(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description',
                                           type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        """
        Objective:  To verify if User registered with their own Email id
        :param request: token
        :return: verification message if verified or error if not verified
        """
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.is_active = True
                user.save()
                return Response(status=status.HTTP_200_OK, data={"msg": "successfully activated"})
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error': 'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Something went wrong, try again later'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginAPIView(generics.GenericAPIView):
    """
    Objective:  To login User
    :param request: Email and password
    :return: access token and refresh token
    """
    serializer_class = LoginSerializer

    def post(self, request):
        """ Take user credentials and authenticate it to login  """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data
        return Response(data=user_data, status=status.HTTP_200_OK)


class ResetPassword(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user_data = serializer.data
            user = User.objects.get(email=user_data['email'])
            password = user_data['password']
            current_site = get_current_site(request).domain
            relative_link = reverse('new_pass')
            token = RefreshToken.for_user(user).access_token
            email_body = "hii \n" + user.username + "Use the link below to reset password: \n" + 'http://' + current_site + relative_link + "?token=" + str(
                token) + "&password=" + password
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': "Reset password Link"}
            send_email.delay(data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(
            {"status": status.HTTP_400_BAD_REQUEST, "message": None, "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST, )


class NewPassword(generics.GenericAPIView):
    serializer_class = NewPasswordSerializer
    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description',
                                           type=openapi.TYPE_STRING)
    password_param_config = openapi.Parameter('password', in_=openapi.IN_QUERY, description='Description',
                                              type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config, password_param_config])
    def get(self, request):
        token = request.GET.get('token')
        password = request.GET.get('password')

        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            user.set_password(password)
            user.save()

            return Response({'email': 'New password is created'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Link is Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error': 'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)
