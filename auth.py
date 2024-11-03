from functools import wraps
from flask import request, jsonify, current_app
import jwt
from models import User
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        auth_header = request.headers.get('Authorization', None)
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'message': 'Token needed!'}), 401

        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['id']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid Token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

def authenticate(username, password):
    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return None

    token = jwt.encode(
        {
            'id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        },
        current_app.config['SECRET_KEY'],
        algorithm="HS256"
    )

    return token
