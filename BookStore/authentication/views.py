import jwt
from django.contrib.auth import authenticate, login
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import generics, status, views
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    @csrf_exempt
    def post(self, request):
        """
        Objective: Register a new User
        :param request:
        :return:
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
            Util.send_email(data)
            return Response(user_data, status=status.HTTP_201_CREATED)
        return Response(status=status.HTTP_200_OK, data={'msg': serializer.errors})


class VerifyEmail(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description',
                                           type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response(status=status.HTTP_200_OK, data={"msg": "successfully activated"})
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error': 'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Unknown Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginAPIView(generics.GenericAPIView):
    """
        API to login with valid credentials
    """
    serializer_class = LoginSerializer

    def post(self, request):
        """ Take user credentials and authenticate it to login  """

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data
        user = authenticate(email=user_data['email'], password=user_data['password'])
        user_data['username'] = user.username
        login(request, user)
        return Response(user_data, status=status.HTTP_200_OK)
