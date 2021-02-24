from __future__ import absolute_import, unicode_literals
from celery import shared_task
from time import sleep

from django.core.mail import EmailMessage

from .models import *


@shared_task
def add(x, y):
    return x + y


@shared_task
def send_email(data):
    email = EmailMessage(subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
    email.send()
