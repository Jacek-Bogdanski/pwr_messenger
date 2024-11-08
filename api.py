import jwt
import datetime
from flask import Blueprint, request, jsonify, render_template, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Message
from auth import token_required
from rsa import mod_exp, decimal_to_hex, encrypt, modular_inverse, get_key_pair, decrypt

routes = Blueprint('routes', __name__)

# test page with encryption test procedure
@routes.route('/testpage', methods=['GET'])
def testpage():
    return render_template('testpage.html')

@routes.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password') or not data.get('n') or not data.get('e'):
        return jsonify({'message': 'Not enough data to register. username, password, n, e!'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User with this username already exists!'}), 400

    hashed_password = generate_password_hash(data['password'], method='pbkdf2')

    new_user = User(
        username=data['username'],
        password=hashed_password,
        n=data['n'],
        e=data['e']
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registered succesfull!'}), 200


def authenticate(username, password):
    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return None
    
    p = current_app.config['SERVER_RSA_P']
    q= current_app.config['SERVER_RSA_Q']
    n = p * q

    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        'id': user.id,   
        'username': user.username,
        'exp': expiration,
        'e': current_app.config['SERVER_RSA_E'],
        'n': n
    }

    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

    return token

@routes.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password needed!'}), 400

    token = authenticate(data['username'], data['password'])

    if not token:
        return jsonify({'message': 'Bad username or password!'}), 401

    return jsonify({'token': token}), 200

@routes.route('/message/conversations', methods=['POST'])
@token_required
def send_message(current_user):
    data = request.get_json()

    if not data or not data.get('content') or not data.get('receiver'):
        return jsonify({'message': 'Brak wymaganych danych!'}), 400

    receiver = User.query.filter_by(username=data['receiver']).first()
    if not receiver:
        return jsonify({'message': 'Receiver does not exist!'}), 404

    P = current_app.config['SERVER_RSA_P']
    Q = current_app.config['SERVER_RSA_Q']
    E = current_app.config['SERVER_RSA_E']
    N, D = get_key_pair(P, Q, E)
    
    new_message = Message(
        content=decrypt(data['content'], D, N),
        sender_id=current_user.id,
        receiver_id=receiver.id
    )
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'Message sent!'}), 200

@routes.route('/message/conversations', methods=['GET'])
@token_required
def get_conversations(current_user):
    sent = current_user.sent_messages.all()
    received = current_user.received_messages.all()

    participants = set()
    for msg in sent:
        participants.add(User.query.get(msg.receiver_id).username)
    for msg in received:
        participants.add(User.query.get(msg.sender_id).username)

    return jsonify({'conversations': list(participants)}), 200

@routes.route('/message/conversations/<participant>', methods=['GET'])
@token_required
def get_conversation_messages(current_user, participant):
    participant_user = User.query.filter_by(username=participant).first()
    if not participant_user:
        return jsonify({'message': 'User does not exists!'}), 404

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == participant_user.id)) |
        ((Message.sender_id == participant_user.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    messages_data = []
    for msg in messages:
        messages_data.append({
            'content': encrypt(msg.content,current_user.e, current_user.n),
            'sender': User.query.get(msg.sender_id).username,
            'receiver': User.query.get(msg.receiver_id).username,
            'timestamp': int(msg.timestamp.timestamp())
        })

    return jsonify({'messages': messages_data}), 200

@routes.route('/users', methods=['GET'])
@token_required
def get_users(current_user):
    users = User.query.all()
    users_data = [{'username': user.username} for user in users]

    return jsonify({'users': users_data}), 200
