import base64
import json
import os
import random
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

API_GATEWAY_AGENT_PRIVATE_KEY_PATH = "api_gateway_agent_private_key.pem"
API_GATEWAY_PRIVATE_KEY_PATH = "api_gateway_private_key.pem"
MANAGER_PUBLIC_KEY_PATH = "manager_public_key.pem"

def load_or_create_private_key():
    if os.path.exists(API_GATEWAY_AGENT_PRIVATE_KEY_PATH):
        with open(API_GATEWAY_AGENT_PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        with open(API_GATEWAY_AGENT_PRIVATE_KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    return private_key

def create_public_key(private_key):
    return private_key.public_key()

def load_manager_public_key():
    with open(MANAGER_PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def symmetric_key_encrypt(key, data):
    fernet = Fernet(key)
    if isinstance(data, str):
        data = data.encode()
    return fernet.encrypt(data)


def symmetric_key_decrypt(key, encrypted_data):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)
    if isinstance(decrypted, bytes):
        return decrypted
    else:
        return decrypted.encode()


def send_message(destination_socket, data):
    if not isinstance(data, bytes):
        data = data.encode()

    length = len(data).to_bytes(4, 'big')
    destination_socket.sendall(length + data)

def receive_exact(sock, n):
    received_data = bytearray()

    while len(received_data) < n:
        message_part = sock.recv(n - len(received_data))

        if message_part == b'':
            return None

        received_data.extend(message_part)

    return bytes(received_data)

def receive_message(sock):
    length_bytes = receive_exact(sock, 4)
    if length_bytes is None:
        return None

    message_length = int.from_bytes(length_bytes, 'big')

    if message_length <= 0 or message_length > 10_000_000:
        return None

    return receive_exact(sock, message_length)

def close_socket(connection_socket):
    connection_socket.close()

def send_secure_message(socket, symmetrical_key, data):
    send_message(socket, symmetric_key_encrypt(symmetrical_key, data))

def receive_secure_message(socket, symmetrical_key):
    received_message = receive_message(socket)
    if received_message:
        return symmetric_key_decrypt(symmetrical_key, received_message)
    else:
        return None

def private_key_decrypt(private_key, data):
    return private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def public_key_encrypt(public_key, data):
    if isinstance(data, str):
        data = data.encode()
    return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def base64_encode(data):
    return base64.b64encode(data).decode()

def base64_decode(data):
    return base64.b64decode(data)

def handshake_receiver(public_key, private_key, manager_public_key, destination_socket):
    received_message = json.loads(receive_message(destination_socket).decode())
    message_id = received_message['message_id']
    if received_message['request_code'] == '101':

        verification_code = received_message['verification_code']
        encrypted_verification_code = public_key_encrypt(manager_public_key, verification_code)
        message = {
            'request': 'hand_shake',
            'request_code': '101',
            'response_code': '999',
            'encrypted_verification_code': base64_encode(encrypted_verification_code),
            'public_key': public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                            ).decode(),
            'message_id': message_id
        }
        send_message(destination_socket, json.dumps(message))
        received_message = json.loads(receive_message(destination_socket).decode())
        if (received_message['request_code'] == '101'
                and received_message['response_code'] == '999'
                and received_message['message_id'] == message_id):
            symmetrical_key = private_key_decrypt(private_key, base64_decode(received_message['encrypted_symmetrical_key']))
            signed_symmetrical_key = symmetric_key_decrypt(symmetrical_key,
                                                           base64_decode(received_message['encrypted_signed_symmetrical_key']))
            if verify_signature(manager_public_key, signed_symmetrical_key, symmetrical_key):
                message = {
                    'request': 'hand_shake',
                    'request_code': '101',
                    'response_code': '999',
                    'message_id': message_id
                }
                send_message(destination_socket, json.dumps(message))
                return symmetrical_key
            else:
                return None
    message = {
        'request': 'hand_shake',
        'request_code': '101',
        'response_code': '998',
        'message_id': message_id
    }
    send_message(destination_socket, json.dumps(message))
    close_socket(destination_socket)
    return None

# API GATEWAY

class Api_Gateway_Private_Key:
    _private_key = None
    _lock = threading.Lock()

    @classmethod
    def get_private_key(cls):
        if cls._private_key is None:
            with cls._lock:
                if cls._private_key is None:
                    with open(API_GATEWAY_PRIVATE_KEY_PATH, "rb") as f:
                        cls._private_key = serialization.load_pem_private_key(
                            f.read(),
                            password=None
                        )
        return cls._private_key


def generate_symmetrical_key():
    return Fernet.generate_key()

def sign_message(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def handshake_sender(private_key, client_socket, message_id):
    verification_code = str(random.randint(10000, 99999))
    message = {'request': 'hand_shake',
               'request_code': '101',
               'response_code': '999',
               'verification_code': verification_code,
               'message_id': message_id}
    send_message(client_socket, json.dumps(message))
    received_message = json.loads(receive_message(client_socket).decode())
    if (received_message['request_code'] == '101'
            and private_key_decrypt(private_key, base64_decode(received_message['encrypted_verification_code'])).decode() == verification_code
            and received_message['message_id'] == message_id
            and received_message['response_code'] == '999'):
        agent_public_key = serialization.load_pem_public_key(received_message.get('public_key').encode())
        symmetrical_key = generate_symmetrical_key()
        signed_symmetrical_key = sign_message(private_key, symmetrical_key)
        encrypted_signed_symmetrical_key = symmetric_key_encrypt(symmetrical_key, signed_symmetrical_key)
        encrypted_symmetrical_key = public_key_encrypt(agent_public_key, symmetrical_key)
        message = {'request': 'hand_shake',
                   'request_code': '101',
                   'response_code': '999',
                   'encrypted_signed_symmetrical_key': base64_encode(encrypted_signed_symmetrical_key),
                   'encrypted_symmetrical_key': base64_encode(encrypted_symmetrical_key),
                   'message_id': message_id}

        send_message(client_socket, json.dumps(message))
        raw_received_message = receive_message(client_socket).decode()
        if raw_received_message is None:
            return None

        received_message = json.loads(raw_received_message)
        if (received_message['request_code'] == '101'
                and received_message['message_id'] == message_id
                and received_message['response_code'] == '999'):
            return agent_public_key, symmetrical_key
        else:
            close_socket(client_socket)
            return None
    else:
        message = {'request': 'hand_shake',
                   'request_code': '101',
                   'response_code': '998',
                   'message_id': message_id}
        send_message(client_socket, json.dumps(message))
        close_socket(client_socket)
        return None