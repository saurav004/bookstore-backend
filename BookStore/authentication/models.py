from django.core.validators import MinLengthValidator
from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager, PermissionsMixin)
from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None, mobile_number=None):
        if email is None:
            raise ValueError('User Must Have an email address')

        user = self.model(username=username, email=self.normalize_email(email), mobile_number=mobile_number)
        user.mobile_number = mobile_number
        user.set_password(password)

        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password, mobile_number=None):
        user = self.create_user(username, email, password=password, mobile_number=mobile_number)
        user.is_active = True
        user.is_superuser = True
        user.is_verified = True
        user.is_staff = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    mobile_number = models.CharField(validators=[MinLengthValidator(10)], max_length=15)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        return RefreshToken.for_user(self).access_token
