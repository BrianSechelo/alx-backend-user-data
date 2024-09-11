#!/usr/bin/env python3
"""
Module to hash password and interact with auth db
"""
from db import DB
from user import User
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
import uuid
from typing import TypeVar

def _hash_password(password: str) ->bytes:
    """
    Hashes a password using bcrypt:

    password: Raw unhashed password.
    return: Hashed pasword as bytes.
    """

    encoded_pwd = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_pwd = bcrypt.hashpw(encoded_pwd, salt)
    return hashed_pwd

def _generate_uuid() -> str:
    """doc doc doc"""
    return str(uuid.uuid4())


UserT = TypeVar("UserT", bound=User)

class Auth:
    """
    Auth class to interact with the authentication database.
    """
    def __init__(self) -> None:
        """
        Initialize Auth instance.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user and returns a user object.
        email: registers users email
        password: registers users password
        return: user's object
        raises: raises ValueError of user exists
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            user = self._db.add_user(email, _hash_password(password))
            return user

    def create_session(self, email: str) -> str:
        """doc doc doc"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None
