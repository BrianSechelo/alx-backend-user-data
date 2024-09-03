#!/usr/bin/env python3
"""Module to handle basic authentication."""

import base64
from typing import TypeVar, Optional
from api.v1.auth.auth import Auth
from models.user import User  # Ensure you have the User model imported


class BasicAuth(Auth):
    """BasicAuth class for handling Basic Authentication."""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        # Code for extract_base64_authorization_header

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        # Code for decode_base64_authorization_header

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        # Code for extract_user_credentials

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

        if user_pwd is None or not isinstance(user_pwd, str):
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

        if user_pwd is None or not isinstance(user_pwd, str):
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
