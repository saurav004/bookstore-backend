from django.http import HttpResponse
from django.shortcuts import render


# Create your views here.

def home(request):
    """
    :param request:
    :return: html
    """
    return HttpResponse('<h1>Home</h1>')
