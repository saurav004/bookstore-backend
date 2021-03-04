from .JWTAuthentication import JWTAuth
from rest_framework import status
from django.urls import reverse
from .models import User
import redis
from django.http import JsonResponse

import sys

sys.path.append('..')
# Connect to our Redis instance
from BookStore import settings

redis_instance = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT)


class TokenAuthentication(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request, *args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            jwt_data = JWTAuth.verify_token(token)
            try:
                cache_token = redis_instance.hget('user_token', jwt_data.get('email'))
            except Exception as e:
                return JsonResponse({'data': 'You have to login to access this resource'},
                                    status=status.HTTP_401_UNAUTHORIZED)
            if cache_token:
                cache_token = cache_token.decode('utf-8')
            if jwt_data and cache_token == token:
                user = User.objects.get(email=jwt_data.get('email'))
                request.META['user'] = user
                return self.get_response(request, *args, **kwargs)
        return JsonResponse({'data': 'You have to login to access this resource'}, status=status.HTTP_401_UNAUTHORIZED)
