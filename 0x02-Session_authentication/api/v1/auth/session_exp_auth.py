#!/usr/bin/env python3
"""
SessionExpAuth class with session expiration handling.
"""
from datetime import datetime, timedelta
from os import getenv
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """Session authentication class with expiration"""
    
    def __init__(self):
        """Initialize with session duration from environment variable"""
        super().__init__()
        try:
            self.session_duration = int(getenv('SESSION_DURATION', 0))
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """Create a session with expiration time"""
        session_id = super().create_session(user_id)
        if session_id is None:
            return None
        
        # Store session dictionary with user_id and created_at
        session_data = {
            "user_id": user_id,
            "created_at": datetime.now()
        }
        self.user_id_by_session_id[session_id] = session_data
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Return user_id if the session is valid and not expired"""
        if session_id is None:
            return None
        
        session_data = self.user_id_by_session_id.get(session_id)
        if session_data is None:
            return None
        
        if self.session_duration <= 0:
            return session_data.get('user_id')

        created_at = session_data.get('created_at')
        if created_at is None:
            return None
        
        # Check if the session has expired
        if created_at + timedelta(seconds=self.session_duration) < datetime.now():
            return None

        return session_data.get('user_id')
