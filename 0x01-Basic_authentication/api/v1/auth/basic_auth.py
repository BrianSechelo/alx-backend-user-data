#!/usr/bin/env python3
"""Module to handle basic authentication."""

from api.v1.auth.auth import Auth


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
