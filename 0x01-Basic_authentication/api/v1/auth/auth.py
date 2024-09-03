#!/usr/bin/env python3
"""Module to manage API authentication."""
from typing import List, TypeVar
from flask import request

class Auth:
    """Class to manage the authentication for APIs."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if authentication is required for a given path.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): The list of paths that do not require authentication.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != "/":
            path += "/"

        for excluded_path in excluded_paths:
            if excluded_path.endswith("*"):
                if path.startswith(excluded_path[:-1]):
                    return False
            elif path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Gets the Authorization header from the request."""
        if request is None:
            return None
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar("User"):
        """Gets the current user from the request."""
        return None
