from django.test import TestCase, Client
import json
from django.urls import reverse
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed

from ..models import User

client = Client()


class TestAuthentication(TestCase):

    def setUp(self):
        self.valid_user_data = {'username': 'Kumar Saurav', 'email': 'logtosaurav@gmail.com', 'password': 'qwerty',
                                'mobile_number': '+91 9284543205'}
        self.invalid_user_data = {'username': 'Kumar Saurav', 'email': 'logtosaurav@gmail.com', 'password': 'qwerty',
                                  'mobile_number': '+91 9284543205'}

        self.valid_login_user_data = {'email': 'logtosaurav@gmail.com', 'password': 'qwerty'}

        self.invalid_login_user_data = {'email': 'logtosaurav@gmail.com', 'password': 'password'}

    def test_register_api_when_valid_data_is_passed(self):
        response = client.post(
            reverse('register'),
            data=json.dumps(self.valid_user_data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_register_api_when_invalid_data_is_passed(self):
        response = client.post(
            reverse('register'),
            data=json.dumps(self.invalid_user_data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_admin_login_when_given_valid_credential(self):
        self.valid_admin_credential = json.dumps({
            'email': 'logtosaurav@gmail.com',
            'password': 'qwerty'
        })
        response = self.client.post(reverse('login'), data=self.valid_login_user_data, content_type='application/json')
        self.assertEquals(response.status_code, status.HTTP_200_OK)

    def test_admin_login_when_given_invalid_credential(self):
        self.valid_admin_credential = json.dumps({
            'email': 'logtosaurav@gmail.com',
            'password': 'password'
        })
        response = self.client.post(reverse('login'), data=self.invalid_login_user_data,
                                    content_type='application/json')
        self.assertEquals(response.status_code, status.HTTP_401_UNAUTHORIZED)
