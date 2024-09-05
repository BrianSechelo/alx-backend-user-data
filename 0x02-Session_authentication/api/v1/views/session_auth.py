#!/usr/bin/env python3
"""
View for Session Authentication
"""
from flask import jsonify, request, abort
from models.user import User
from os import getenv
from api.v1.views import app_views
from flask import make_response

@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login():
    """
    Handle POST /auth_session/login
    """
    from api.v1.app import auth

    email = request.form.get('email')
    password = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400

    if not password:
        return jsonify({"error": "password missing"}), 400

    users = User.search({'email': email})
    if not users or len(users) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]

    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    session_id = auth.create_session(user.id)

    user_json = user.to_json()

    response = make_response(jsonify(user_json))
    session_name = getenv("SESSION_NAME", "_my_session_id")
    response.set_cookie(session_name, session_id)

    return response

@app_views.route('/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def session_logout():
    """
    Handle DELETE /auth_session/logout
    """
    from api.v1.app import auth  # Importing auth here to avoid circular import

    if not auth.destroy_session(request):
        abort(404)

    return jsonify({}), 200
