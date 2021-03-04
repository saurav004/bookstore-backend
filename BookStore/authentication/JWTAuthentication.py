import jwt
from datetime import datetime, timedelta
import environ

env = environ.Env()
# reading .env file
environ.Env.read_env()


class JWTAuth:
    """ This is used for getting token and verify token"""

    @staticmethod
    def get_token(email, password, secret_key=env('SECRET_KEY')):
        """
        This function is used for getting user token
        :param email: user's email
        :param password: user's password
        :param secret_key: secret key
        :return: JWT authentication token
        """
        data = {
            'email': email,
            'password': password,
            'exp': datetime.utcnow() + timedelta(days=2)
        }
        jwt_token = jwt.encode(data, key=secret_key)
        return jwt_token

    @staticmethod
    def verify_token(jwt_token, secret_key=env('SECRET_KEY')):
        """
        This function is used for verify user token for authorization
        :param jwt_token: Token
        :param secret_key: secret key
        :return: verify token
        """
        try:
            decode_value = jwt.decode(jwt_token, key=secret_key, algorithms='HS256')
            return decode_value
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False
