#!/usr/bin/env python3
"""
Module to run flask app
"""
from flask import Flask, jsonify, request, make_response
from flask import abort, Response, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()

@app.route("/")
def home() -> Response:
    """
    Route to home
    """
    message = {"mesage": "Bienvenue"}
    return jsonify(message)

@app.route("/users", methods=["POST"])
def users() -> Response:
    """doc doc doc"""
    email = request.form["email"]
    password = request.form["password"]
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400

@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> Response:
    """doc doc doc"""
    email = request.form.get("email")
    password = request.form.get("password")

    if AUTH.valid_login(email, password):
        jsoni = jsonify({"email": email, "message": "logged in"}), 200
        response = make_response(jsoni)
        response.set_cookie("session_id", AUTH.create_session(email))
        return response

    abort(401)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
