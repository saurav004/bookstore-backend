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
    new_password = serializers.CharField(max_length=68, min_length=8)
    token = serializers.CharField(max_length=200, min_length=6)

    class Meta:
        model = User
        fields = ['new_password', 'token']

    def validate(self, attrs):
        token = attrs.get('token')
        new_password = attrs.get('new_password', '')
        if token is None:
            raise serializers.ValidationError("token invalid")
        if new_password is None:
            raise serializers.ValidationError("new password cannot be empty")
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(max_length=20, min_length=6)
    new_password = serializers.CharField(max_length=20, min_length=6)

    def validate(self, attrs):
        current_password = attrs.get('current_password', '')
        new_password = attrs.get('current_password', '')
        if current_password is None:
            raise serializers.ValidationError("current password cannot be empty")
        if new_password is None:
            raise serializers.ValidationError("new password cannot be empty")
        return attrs


class LogoutSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=200, min_length=6)

    class Meta:
        model = User
        fields = ['token']

    def validate(self, data):
        if data.get('token') is None:
            raise serializers.ValidationError("Token is not valid")
        return data
