import base64
import json
import os
import random

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

PRIVATE_KEY_PATH = 'default_manager_private_key.pem'
DATABASE_SYMMETRICAL_KEY_PATH = 'database_symmetrical_key.key'

def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def generate_symmetrical_key():
    return Fernet.generate_key()

def load_symmetrical_key():
    if os.path.exists(DATABASE_SYMMETRICAL_KEY_PATH):
        with open(DATABASE_SYMMETRICAL_KEY_PATH, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(DATABASE_SYMMETRICAL_KEY_PATH, "wb") as f:
            f.write(key)
    return key

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


def public_key_encrypt(public_key, data):
    return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

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


def sign_message(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def base64_encode(data):
    return base64.b64encode(data).decode()

def base64_decode(data):
    return base64.b64decode(data.encode())

def handshake_sender(private_key, agent_socket, message_id):
    verification_code = str(random.randint(10000, 99999))
    message = {'request': 'hand_shake',
               'request_code': '101',
               'response_code': '999',
               'verification_code': verification_code,
               'message_id': message_id}
    send_message(agent_socket, json.dumps(message))
    received_message = json.loads(receive_message(agent_socket).decode())
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
        send_message(agent_socket, json.dumps(message))
        received_message = json.loads(receive_message(agent_socket).decode())
        if (received_message['request_code'] == '101'
                and received_message['message_id'] == message_id
                and received_message['response_code'] == '999'):
            return agent_public_key, symmetrical_key
        else:
            close_socket(agent_socket)
            return None
    else:
        message = {'request': 'hand_shake',
                   'request_code': '101',
                   'response_code': '998',
                   'message_id': message_id}
        send_message(agent_socket, json.dumps(message))
        close_socket(agent_socket)
        return None