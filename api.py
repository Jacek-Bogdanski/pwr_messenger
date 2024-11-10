import jwt
import datetime
from flask import Blueprint, request, jsonify, render_template, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Message
from auth import token_required, authenticate
from rsa import mod_exp, decimal_to_hex, encrypt, modular_inverse, get_key_pair, decrypt

routes = Blueprint('routes', __name__)

# test page with encryption test procedure
@routes.route('/testpage', methods=['GET'])
def testpage():
    return render_template('testpage.html')

@routes.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Not enough data to register. username, password!'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User with this username already exists!'}), 400

    hashed_password = generate_password_hash(data['password'], method='pbkdf2')

    new_user = User(
        username=data['username'],
        password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registered succesfull!'}), 200

def encode_public_key(n, e):
    max_length = max(len(str(n)), len(str(e)))
    n_str = str(n).zfill(max_length)
    e_str = str(e).zfill(max_length)
    return int(n_str + e_str)

def decode_public_key(encoded_num):
    encoded_str = str(encoded_num)
    half_length = len(encoded_str) // 2
    n = int(encoded_str[:half_length])
    e = int(encoded_str[half_length:])
    return n, e

def get_server_pub():
    p = current_app.config['SERVER_RSA_P']
    q= current_app.config['SERVER_RSA_Q']
    n = p * q
    return encode_public_key(n, current_app.config['SERVER_RSA_E'])


@routes.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password needed!'}), 400
    
    if not data or not data.get('username') or not data.get('password') or not data.get('clientPub'):
        return jsonify({'message': 'Not enough data to login. username, password, clientPub!'}), 400
    
    token = authenticate(data['username'], data['password'], data['clientPub'], get_server_pub())

    if not token:
        return jsonify({'message': 'Bad username or password!'}), 401

    return jsonify({'token': token}), 200

@routes.route('/message/conversations', methods=['POST'])
@token_required
def send_message(current_user, client_pub):
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
def get_conversations(current_user, client_pub):
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
def get_conversation_messages(current_user, client_pub, participant):
    participant_user = User.query.filter_by(username=participant).first()
    if not participant_user:
        return jsonify({'message': 'User does not exists!'}), 404

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == participant_user.id)) |
        ((Message.sender_id == participant_user.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    n, e = decode_public_key(client_pub)
    
    messages_data = []
    for msg in messages:
        messages_data.append({
            'content': encrypt(msg.content,e, n),
            'contentPlainText': msg.content,
            'sender': User.query.get(msg.sender_id).username,
            'receiver': User.query.get(msg.receiver_id).username,
            'timestamp': int(msg.timestamp.timestamp())
        })

    return jsonify({'messages': messages_data}), 200

@routes.route('/users', methods=['GET'])
@token_required
def get_users(current_user, client_pub):
    users = User.query.all()
    users_data = [{'username': user.username} for user in users]

    return jsonify({'users': users_data}), 200
