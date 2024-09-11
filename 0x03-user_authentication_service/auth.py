#!/usr/bin/env python3
"""
Module to hash password and interact with auth db
"""
import bcrypt
from sqlalchemy.exc import NoResultFound
from db import DB
from user import User

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
