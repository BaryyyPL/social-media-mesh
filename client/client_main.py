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
    close_socket,
    base64_encode
)

from render_message_methods import (
    render_registration_message,
    render_login_message,
    render_upload_posts_message,
    render_read_posts_message,
    render_upload_files_message,
    render_download_files_message,
    render_available_files_message,
    render_delete_account_message
)

MAX_FILE_SIZE = 5 * 1024 * 1024  # =5MB

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
    if not any(c in '!@#$%^&*()-_=+[]{};:,.<>?/|' for c in password):
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
        self.user_id = 1
        self.login = None
        self.api_gateway_socket = self.connect_to_server()

    def run(self):
        try:
            self.select_options()
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
        api_gateway_socket.settimeout(60.0)
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
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f'Connection to API Gateway lost - {e}.')
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
            self.user_id = None
            print('Client stopped.')
            raise SystemExit

    def select_options(self):
        while self.flag:

            if self.user_id is None:

                print('\n1. Registration\n2. Log in\n3. Help\n4. Exit')
                option = input('Choose an option: ')

                if option == '1':

                    service_type = 'registration_service'

                    while True:
                        login = input('Login: ')
                        password = input('Password (Minimum 5 characters): ')
                        repeat_password = input('Repeat password: ')

                        if not login or not password or not repeat_password:
                            break

                        if validate_password(password) and password == repeat_password:
                            data = {
                                'login': login,
                                'password': password
                            }
                            self.communication(service_type, data)
                            break

                        clear_console()
                        print('Incorrect password format.')


                elif option == '2':

                    service_type = 'login_service'
                    login = input('Login: ')
                    password = input('Password: ')

                    if login and password:
                        data = {
                            'login': login,
                            'password': password
                        }

                        self.communication(service_type, data)


                elif option == '3':

                    print('To exit the operation, leave the fields blank and press ENTER.')

                else:
                    self.disconnect_with_api_gateway()
                    stop_client()

            else:

                print(f'\nLogin as {self.login}')
                print('1. Upload post\n2. Read posts\n3. Upload file\n4. Download file\n'
                      '5. Available files\n6. Logout\n7. Help\n8. Delete account\n9. Exit')
                option = input('Choose an option: ')

                if option == '1':

                    service_type = 'upload_posts_service'

                    contents = input('Write your post: ')

                    if contents:
                        data = {
                            'contents': contents,
                            'id': self.user_id
                        }

                        self.communication(service_type, data)


                elif option == '2':

                    service_type = 'read_posts_service'
                    number = input('Write number of posts (type number or "ALL" for all available posts): ')

                    if number:

                        if number.isnumeric() or number.lower() == 'all':

                            data = {
                                'number': number
                            }

                            self.communication(service_type, data)

                        else:
                            clear_console()
                            print('Wrong number')

                elif option == '3':

                    service_type = 'upload_files_service'
                    file_path = input('Path to file: ')
                    description = input('Description (optional):')

                    if file_path:

                        if not os.path.isfile(file_path):
                            clear_console()
                            print('File does not exist')

                        else:

                            with open(file_path, 'rb') as f:
                                file_bytes = f.read()

                            if len(file_bytes) > MAX_FILE_SIZE:
                                clear_console()
                                print('File is too big')

                            else:

                                encoded_file = base64_encode(file_bytes)

                                data = {
                                    'id': self.user_id,
                                    'filename': os.path.basename(file_path),
                                    'file': encoded_file,
                                    'description': description
                                }

                                self.communication(service_type, data)

                elif option == '4':

                    service_type = 'download_files_service'

                    filename = input('Filename to download: ')

                    if filename:
                        data = {
                            'filename': filename
                        }
                        self.communication(service_type, data)

                elif option == '5':

                    service_type = 'available_files_service'

                    self.communication(service_type, {})

                elif option == '6':

                    self.user_id = None

                elif option == '7':

                    print('To exit the operation, leave the fields blank and press ENTER.')

                elif option == '8':
                    service_type = 'delete_account_service'
                    print('Are you sure you want to delete your account? '
                          '\nIf so, confirm the operation by entering your password. '
                          '\nOtherwise, leave the field blank and press ENTER.')
                    password = input('Password: ')

                    if password:
                        data = {
                            'id': self.user_id,
                            'password': password
                        }

                        self.communication(service_type, data)

                else:
                    self.disconnect_with_api_gateway()
                    stop_client()

    def communication(self, service_type, data):
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

            match service_type:
                case 'registration_service':
                    render_registration_message(response)

                case 'login_service':
                    self.user_id, self.login = render_login_message(response)

                case 'upload_posts_service':
                    render_upload_posts_message(response)

                case 'read_posts_service':
                    render_read_posts_message(response)

                case 'upload_files_service':
                    render_upload_files_message(response)

                case 'download_files_service':
                    render_download_files_message(response)

                case 'available_files_service':
                    render_available_files_message(response)

                case 'delete_account_service':
                    if render_delete_account_message(response):
                        self.user_id = None

                case _:
                    print('Error')

        else:
            print('Error in response.')

        print(f'Elapsed time: {elapsed_ns} ns | {elapsed_ms:.3f} ms | {elapsed_s:.6f} s')


client = Client()
client.run()
