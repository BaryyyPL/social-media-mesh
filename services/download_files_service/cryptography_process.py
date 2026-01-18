import base64
import json
import os
import socket

import bcrypt
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PRIVATE_KEY_PATH = "download_files_service_agent_private_key.pem"
PUBLIC_KEY_PATH = "manager_public_key.pem"

def load_or_create_private_key():
    if os.path.exists(PRIVATE_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    return private_key

def verify_filename(rows, filename):
    for row in rows:
        file_id = row['id']
        filename_hash = row['filename_hash']
        if bcrypt.checkpw(
            filename.encode('utf-8'),
            filename_hash.encode('utf-8')):

            return file_id

    return None

def create_public_key(private_key):
    return private_key.public_key()

def load_manager_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
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
        try:
            message_part = sock.recv(n - len(received_data))
        except socket.timeout:
            return None

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
    return public_key.encrypt(
            data.encode(),
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

def handshake_receiver(public_key, private_key, manager_public_key, manager_socket):
    received_message = json.loads(receive_message(manager_socket).decode())
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
        send_message(manager_socket, json.dumps(message))
        received_message = json.loads(receive_message(manager_socket).decode())
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
                send_message(manager_socket, json.dumps(message))
                return symmetrical_key
            else:
                return None
    message = {
        'request': 'hand_shake',
        'request_code': '101',
        'response_code': '998',
        'message_id': message_id
    }
    send_message(manager_socket, json.dumps(message))
    close_socket(manager_socket)
    return None