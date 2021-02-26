from django.test import TestCase, Client
import json
from django.urls import reverse
from rest_framework import status
from ..models import User

client = Client()


class TestAuthentication(TestCase):

    def setUp(self):
        self.user_data = {'username': 'Kumar Saurav', 'email': 'logtosaurav@gmail.com', 'password': 'qwerty',
                          'mobile_number': '+91 9284543205'}

    def test_park(self):
        response = client.post(
            reverse('register'),
            data=json.dumps(self.user_data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
