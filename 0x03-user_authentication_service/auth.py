#!/usr/bin/env python3
"""
Module to hash password and interact with auth db
"""
import bcrypt
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
