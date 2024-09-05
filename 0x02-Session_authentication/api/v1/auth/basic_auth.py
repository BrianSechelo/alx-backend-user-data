#!/usr/bin/env python3
"""Module to handle basic authentication."""

import base64
from typing import TypeVar, Optional
from api.v1.auth.auth import Auth
from models.user import User  # Ensure you have the User model imported


class BasicAuth(Auth):
    """BasicAuth class for handling Basic Authentication."""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization header.

        Args:
            authorization_header (str): The Authorization header string.

        Returns:
            str: The Base64 part of the Authorization header or None if conditions are not met.
        """
        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        # Return the Base64 part, which is everything after "Basic "
        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """
        Decodes the Base64 part of the Authorization header.

        Args:
            base64_authorization_header (str): The Base64 string to decode.

        Returns:
            str: The decoded value as a UTF-8 string, or None if conditions are not met.
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            # Decode the Base64 string
            decoded_bytes = base64.b64decode(base64_authorization_header)
            # Convert the bytes to a UTF-8 string
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Extracts user email and password from the Base64 decoded value.

        Args:
            decoded_base64_authorization_header (str): The decoded Base64 string.

        Returns:
            tuple: (user_email, user_password) or (None, None) if conditions are not met.
        """
        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        # Split the string at the first ':', so the password can contain colons
        user_email, user_password = decoded_base64_authorization_header.split(':', 1)
        return user_email, user_password

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> Optional[TypeVar('User')]:
        """
        Returns the User instance based on email and password.

        Args:
            user_email (str): The email of the user.
            user_pwd (str): The password of the user.

        Returns:
            User: The User instance if authentication is successful, otherwise None.
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        # Search for the user by email
        user = User.search({'email': user_email})
        if not user:
            return None

        # Assume the search method returns a list; take the first match
        user = user[0]

        # Check if the password is valid
        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> Optional[TypeVar('User')]:
        """
        Retrieves the User instance for a request.

        Args:
            request: The request object containing the Authorization header.

        Returns:
            User: The User instance if authentication is successful, otherwise None.
        """
        # Extract the Authorization header from the request
        authorization_header = self.authorization_header(request)
        if authorization_header is None:
            return None

        # Extract the Base64 part from the Authorization header
        base64_authorization_header = self.extract_base64_authorization_header(authorization_header)
        if base64_authorization_header is None:
            return None

        # Decode the Base64 string to a UTF-8 string
        decoded_base64_authorization_header = self.decode_base64_authorization_header(base64_authorization_header)
        if decoded_base64_authorization_header is None:
            return None

        # Extract the user credentials (email and password)
        user_email, user_password = self.extract_user_credentials(decoded_base64_authorization_header)
        if user_email is None or user_password is None:
            return None

        # Retrieve and return the User instance
        return self.user_object_from_credentials(user_email, user_password)
