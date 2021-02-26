import datetime
import jwt
import redis
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import generics, status
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer, ResetPasswordEmailSerializer, \
    NewPasswordSerializer, ChangePasswordSerializer, LogoutSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .tasks import send_email
import logging

logger = logging.getLogger('django')

# Connect to our Redis instance
redis_instance = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT)


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
        try:
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
                return Response(data={"message": "user created", "errors": None, "data": user_data},
                                status=status.HTTP_201_CREATED)
            logger.debug(serializer.errors)
            return Response(data={"message": None, "errors": serializer.errors, "data": None},
                            status=status.HTTP_400_BAD_REQUEST, )
        except ValidationError:
            return Response(data={"message": None, "errors": serializer.errors, "data": None},
                            status=status.HTTP_400_BAD_REQUEST, )
        except Exception as e:
            logger.exception(e)
            return Response(data={"message": None, "errors": 'Something went wrong, try again later', 'data': None},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
            return Response(data={"message": None, "errors": 'Activation Expired', 'data': None},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response(data={"message": None, "errors": 'Invalid Token', 'data': None},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(e)
            return Response(data={"message": None, "errors": 'Something went wrong, try again later', 'data': None},
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
        redis_instance.hmset('user_token', {"auth": str(user_data['token'])})
        redis_instance.expire(user_data['email'], time=datetime.timedelta(days=2))
        logger.info(redis_instance.hmget(user_data['email'], 'auth'))
        return Response(data={"message": 'LogIn successful', "errors": None, 'data': user_data},
                        status=status.HTTP_200_OK)


class ResetPassword(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user_data = serializer.data
            user = User.objects.get(email=user_data['email'])
            current_site = get_current_site(request).domain
            relative_link = reverse('new_password')
            token = RefreshToken.for_user(user).access_token
            absurl = 'http://' + current_site + relative_link + "?token=" + str(token)
            email_body = "hii \n" + user.username + "Use the link below to reset password: \n" + absurl
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': "Reset password Link"}
            send_email.delay(data)
            return Response(data={"message": 'link sent to email', "errors": None, 'data': serializer.data},
                            status=status.HTTP_200_OK)
        return Response(data={"message": None, "errors": serializer.errors, 'data': None},
                        status=status.HTTP_400_BAD_REQUEST, )


class NewPassword(generics.GenericAPIView):
    serializer_class = NewPasswordSerializer

    def post(self, request):
        token = request.data.get('token')
        new_password = request.data.get('new_password')

        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            user.set_password(new_password)
            user.save()
            return Response(data={'message': 'New password is created', 'error': None, 'data': None},
                            status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response(data={'message': None, 'error': 'Link is Expired', 'data': None},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response(data={'message': None, 'error': 'Invalid Token', 'data': None},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(e)
            return Response(data={'message': 'Something went wrong, contact admin', 'error': None, 'data': None},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangeUserPassword(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer

    def put(self, request):
        """
        Objective: to change user's current password with the new password
        :param request: current password and new password
        :return: status code , and success or error messages
        """
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            current_password = serializer.data.get('current_password')
            payload = jwt.decode(request.META.get('HTTP_AUTHORIZATION'), settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if check_password(current_password, user.password):
                user.set_password(raw_password=serializer.data.get('new_password'))
                user.save()
                logger.info('password changed successfully')
                return Response(data={'message': 'password changed successfully', 'error': None, 'data': None},
                                status=status.HTTP_200_OK)
            logger.info('Current Password is invalid')
            return Response(
                {'message': 'Current Password is invalid, enter correct password', 'error': None, 'data': None},
                status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response(data={'message': None, 'error': 'token expired login again', 'data': None},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response(data={'message': None, 'error': 'Invalid Token', 'data': None},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(e)
            return Response(data={'message': None, 'error': 'Something went wrong, contact admin', 'data': None},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutUser(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    def get(self, request):
        """
        Objective: this Api is to log the user out and clear the cache
        :param request: authentication token in request header
        :return: status code and success/failure message
        """
        try:
            payload = jwt.decode(request.META.get('HTTP_AUTHORIZATION'), settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if user:
                if redis_instance.hmget('user_token', user.email):
                    redis_instance.delete(user.email)
                    logger.info(f'token deleted {redis_instance.delete(user.email)}')
                    logger.info('logout successful')
                    return Response(
                        data={"message": 'you are logged out successfully', 'errors': None, 'data': None},
                        status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response(
                        data={"message": None, "errors": 'user need to be logged in to logout', 'data': None},
                        status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response(data={"message": None, "errors": 'token Expired', 'data': None},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response(data={"message": None, "errors": 'Invalid Token', 'data': None},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(e)
            return Response(data={"message": None, "errors": 'Something went wrong, try again later', 'data': None},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
