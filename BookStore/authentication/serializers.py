from django.contrib.auth import authenticate
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from .models import User


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'mobile_number']

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')
        if email is None:
            raise serializers.ValidationError('email cannot be empty')
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.EmailField(max_length=255, min_length=3, read_only=True)
    token = serializers.CharField(max_length=68, min_length=6, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'token']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = authenticate(email=email, password=password)
        if user is None:
            raise AuthenticationFailed("Invalid credentials, try again")
        if not user.is_active:
            raise AuthenticationFailed("Account is inactive, contact admin")
        if not user.is_verified:
            raise AuthenticationFailed("Email not verified")

        return {
            "email": user.email,
            "username": user.username,
            "token": user.tokens()
        }


class ResetPasswordEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)

    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email', '')
        user = User.objects.get(email=email)
        if user is None:
            raise serializers.ValidationError("Email not registered")
        if not user.is_verified:
            raise serializers.ValidationError("Email not verified")
        return attrs


class NewPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6)
    password2 = serializers.CharField(max_length=68, min_length=6)

    class Meta:
        model = User
        fields = ['password', 'new_password']

    def validate(self, attrs):
        password = attrs.get('password', '')
        new_password = attrs.get('new_password', '')
        if password == new_password:
            raise serializers.ValidationError("Old Password and New Password should not match!!")
        return attrs
