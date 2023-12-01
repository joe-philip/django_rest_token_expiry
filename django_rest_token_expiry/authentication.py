from datetime import datetime, timedelta

from django.conf import settings
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed


class ExpiringTokenAuthentication(TokenAuthentication):
    """
    Token authentication that supports token expiry.

    This authentication class extends the TokenAuthentication class
    provided by Django REST Framework. It adds support for token expiry
    by checking the expiration time of the token.

    Methods:
        authenticate_credentials(key): Authenticate the credentials using the provided key.
    """
    def authenticate_credentials(self, key):
        """
        Authenticate the credentials using the provided key.

            Args:
                key (str): The authentication key.

            Raises:
                AuthenticationFailed: If the token is invalid, the user is inactive,
                    or the token has expired.

            Returns:
                User: The authenticated user.

            """
        try:
            token = Token.objects.get(key=key)
        except Token.DoesNotExist:
            raise AuthenticationFailed('Invalid Token')
        if (hasattr(token.user, 'is_active')) and (not token.user.is_active):
            raise AuthenticationFailed('Inactive User')
        (now, expiry) = (datetime.now(), settings.AUTHENTICATION_TOKEN_EXPIRY)
        if not isinstance(expiry, timedelta):
            raise ValueError(
                "TOKEN_EXPIRY variable must be a timedelta instance")
        if (token.created + expiry) > now:
            raise AuthenticationFailed('Token Expired')
        return super().authenticate_credentials(key)
