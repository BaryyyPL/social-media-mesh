import json
import os
import socket
import time

from cryptography_process import (
    load_api_gateway_public_key,
    load_or_create_private_key,
    create_public_key,
    handshake_receiver,
    send_secure_message,
    receive_secure_message,
    close_socket
)

api_gateway_host = 'localhost'
list_of_ports_of_api_gateway = [8666, 8667, 8668, 8669, 8670]
maximum_number_of_attempts_for_connect_with_this_port = 3

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def validate_password(password):
    if len(password) < 5:
        return False
    '''if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in "!@#$%^&*()-_=+[]{};:,.<>?/|" for c in password):
        return False'''
    return True


def stop_client():
    raise SystemExit


class Client:
    def __init__(self):
        self.flag = True
        self.private_key = load_or_create_private_key()
        self.public_key = create_public_key(self.private_key)
        self.api_gateway_public_key = load_api_gateway_public_key()
        self.symmetrical_key = None
        self.client_id = None
        self.api_gateway_socket = self.connect_to_server()

    def run(self):
        try:
            self.communication()
        except KeyboardInterrupt:
            print('\nShutting down client - interrupted by user')
            self.flag = False
            if self.api_gateway_socket:
                self.disconnect_with_api_gateway()
            raise SystemExit
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
            print(f'\nShutting down client - connection error: {e}')
            self.flag = False
            if self.api_gateway_socket:
                self.disconnect_with_api_gateway()
            raise SystemExit

    def connect_to_server(self):
        api_gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        api_gateway_socket.settimeout(5.0)
        print('Connecting to API Gateway...')
        while True:
            for api_gateway_port in list_of_ports_of_api_gateway:
                for i in range(maximum_number_of_attempts_for_connect_with_this_port):
                    try:
                        api_gateway_socket.connect((api_gateway_host, api_gateway_port))
                        self.symmetrical_key = handshake_receiver(
                            self.public_key, self.private_key, self.api_gateway_public_key, api_gateway_socket
                        )
                        print(f'Connected to API Gateway at port {api_gateway_port}.')
                        return api_gateway_socket
                    except (ConnectionRefusedError, socket.timeout, OSError):
                        continue

    def send_to_api_gateway(self, message):
        try:
            send_secure_message(self.api_gateway_socket, self.symmetrical_key, message)
        except (ConnectionResetError, BrokenPipeError, OSError):
            print('Failed to send message: connection closed.')
            self.disconnect_with_api_gateway()

    def receive_from_api_gateway(self):
        try:
            received_secure_message = receive_secure_message(self.api_gateway_socket, self.symmetrical_key)
            if received_secure_message:
                return received_secure_message.decode()
            else:
                return None
        except (ConnectionResetError, BrokenPipeError, OSError):
            print('Connection to API Gateway lost.')
            self.disconnect_with_api_gateway()
            return 'error'

    def disconnect_with_api_gateway(self):
        if self.api_gateway_socket is None:
            print('Client stopped.')
            raise SystemExit

        try:
            message = {
                'request': 'disconnect',
                'request_code': '106',
                'service_type': 'service'
            }
            if self.symmetrical_key:
                self.send_to_api_gateway(json.dumps(message))
        except Exception as e:
            print(f'Exception during disconnect: {e}')
        finally:
            try:
                if self.api_gateway_socket:
                    close_socket(self.api_gateway_socket)
            except Exception as e:
                print(f'Exception closing socket: {e}')
            self.api_gateway_socket = None
            self.symmetrical_key = None
            self.client_id = None
            print('Client stopped.')
            raise SystemExit

    def communication(self):
        while self.flag:

            service_type = None
            data = None

            if self.client_id is None:

                print('\n1. Registration\n2. Exit')
                option = input('Choose an option: ')

                if option == '1':

                    service_type = 'registration_service'
                    login = input('Login: ')
                    password = input('Password (Minimum 5 characters): ')

                    while not validate_password(password):
                        clear_console()
                        print('Incorrect password format.')
                        login = input('Login: ')
                        password = input('Password (Minimum 5 characters): ')

                    data = {
                        'login': login,
                        'password': password
                    }

                elif option == '2':

                    service_type = 'login_service'
                    login = input('Login: ')
                    password = input('Password: ')

                    data = {
                        'login': login,
                        'password': password
                    }

                else:
                    self.disconnect_with_api_gateway()
                    stop_client()

            else:
                pass

            message = {
                'request': 'communication',
                'request_code': '105',
                'service_type': service_type,
                'data': data
            }

            start_time_ns = time.perf_counter_ns()

            self.send_to_api_gateway(json.dumps(message))

            raw_response = self.receive_from_api_gateway()
            while raw_response is None:
                raw_response = self.receive_from_api_gateway()
                if raw_response == 'error':
                    print('Connection closed.')
                    return
                time.sleep(0.001)

            end_time_ns = time.perf_counter_ns()
            elapsed_ns = end_time_ns - start_time_ns
            elapsed_ms = elapsed_ns / 1_000_000
            elapsed_s = elapsed_ns / 1_000_000_000

            response = json.loads(raw_response)

            if response['response_code'] == '999' and response['request_code'] == '105':
                print(response['response'])

            else:
                print('Error in response.')

            print(f'Elapsed time: {elapsed_ns} ns | {elapsed_ms:.3f} ms | {elapsed_s:.6f} s')


client = Client()
client.run()
