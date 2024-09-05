#!/usr/bin/env python3
"""
SessionAuth module for handling session-based authentication
"""
import uuid
from api.v1.auth.auth import Auth

class SessionAuth(Auth):
    """Session-based authentication class"""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a session ID for a given user_id and stores it in the dictionary.
        
        Args:
            user_id (str): The user ID to associate with the session ID.
        
        Returns:
            str: The session ID, or None if user_id is invalid.
        """
        if user_id is None or not isinstance(user_id, str):
            return None

        session_id = str(uuid.uuid4())

        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Retrieves the user ID associated with a given session ID.

        Args:
            session_id (str): The session ID for which the user ID needs to be retrieved.

        Returns:
            str: The user ID, or None if session_id is invalid or not found.
        """
        if session_id is None or not isinstance(session_id, str):
            return None

        return self.user_id_by_session_id.get(session_id)
