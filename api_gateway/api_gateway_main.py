import json
import queue
import socket
import threading
import time

from cryptography_process import (
    handshake_sender,
    send_secure_message,
    receive_secure_message,
    Api_Gateway_Private_Key,
    close_socket
)


def get_request_and_request_code(service_type):

    match service_type:
        case 'registration_service':
            return 'registration', '109'

        case 'login_service':
            return 'login', '110'

        case 'upload_posts_service':
            return 'upload_posts', '111'

        case 'read_posts_service':
            return 'read_posts', '112'

        case 'upload_files_service':
            return 'upload_files', '113'

        case 'download_files_service':
            return 'download_files', '114'

        case 'available_files_service':
            return 'available_files', '115'

        case 'delete_account_service':
            return 'delete_account', '116'


class API_Gateway:
    ACCEPT_TIMEOUT = 0.1
    CLIENT_TIMEOUT = 0.1
    SERVICE_TIMEOUT = 30

    def __init__(self, host, port, queue_to_worker, queue_from_worker):
        self.message_id = 0

        # Starting of server
        self.api_gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.api_gateway_socket.bind((host, port))
        self.api_gateway_socket.listen(1)

        self.api_gateway_socket.settimeout(self.ACCEPT_TIMEOUT)

        self.working_status = False

        self.private_key = Api_Gateway_Private_Key.get_private_key()
        self.client_socket = None
        self.client_address = None
        self.client_public_key = None
        self.client_symmetrical_key = None

        self.maximum_number_of_attempts = 3

        self.service_proxy_host = None
        self.service_proxy_port = None
        self.service_proxy_socket = None
        self.service_proxy_symmetrical_key = None

        self.queue_to_worker = queue_to_worker
        self.queue_from_worker = queue_from_worker

        self.stop_flag = False
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            self.communication_with_client()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            self.disconnect_with_client()

    def connect_with_client(self):
        try:
            self.client_socket, self.client_address = self.api_gateway_socket.accept()

            self.client_socket.settimeout(self.CLIENT_TIMEOUT)

            self.client_public_key, self.client_symmetrical_key = handshake_sender(
                self.private_key,
                self.client_socket,
                self.message_id
            )
            if not self.client_public_key or not self.client_symmetrical_key:
                self.client_socket.close()
                return False

            self.message_id += 1
            return True

        except socket.timeout:
            return False

    def connect_to_service_proxy(self):
        service_proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        service_proxy_socket.settimeout(self.SERVICE_TIMEOUT)

        service_proxy_socket.connect((self.service_proxy_host, self.service_proxy_port))
        self.service_proxy_socket = service_proxy_socket

    def send_to_service_proxy(self, message):
        send_secure_message(
            self.service_proxy_socket,
            self.service_proxy_symmetrical_key,
            message
        )

    def receive_from_service_proxy(self):
        try:
            return receive_secure_message(
                self.service_proxy_socket,
                self.service_proxy_symmetrical_key
            )

        except socket.timeout:
            return None

    def send_to_agent(self, message):
        self.queue_from_worker.put(message)

    def receive_from_agent(self):
        try:
            return self.queue_to_worker.get(timeout=1)
        except queue.Empty:
            return None

    def send_to_client(self, message):
        send_secure_message(
            self.client_socket,
            self.client_symmetrical_key,
            message
        )

    def receive_from_client(self):
        try:
            received_secure_message = receive_secure_message(
                self.client_socket,
                self.client_symmetrical_key
            )
            if received_secure_message:
                return received_secure_message.decode()
            else:
                return None

        except socket.timeout:
            return None

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            self.disconnect_with_client()
            return 'error'

    def disconnect_with_service(self):
        message_to_service = {
            'request': 'disconnect',
            'request_code': '106',
            'service_type': 'service'
        }

        self.send_to_service_proxy(json.dumps(message_to_service))
        close_socket(self.service_proxy_socket)

        self.service_proxy_host = None
        self.service_proxy_port = None
        self.service_proxy_socket = None
        self.service_proxy_symmetrical_key = None

    def disconnect_with_client(self):
        close_socket(self.client_socket)

        self.client_socket = None
        self.client_address = None
        self.client_public_key = None
        self.client_symmetrical_key = None

        self.change_working_status(False)

    def communication_with_services(self, message_from_client):
        service_type = message_from_client['service_type']

        request, request_code = get_request_and_request_code(service_type)

        data = message_from_client['data']

        message_to_agent = {
            'request': 'communication',
            'request_code': '105',
            'service_type': service_type
        }
        self.send_to_agent(message_to_agent)

        message_from_agent = None
        while not message_from_agent:
            message_from_agent = self.receive_from_agent()

        self.service_proxy_host = message_from_agent['host']
        self.service_proxy_port = message_from_agent['port']
        self.service_proxy_symmetrical_key = message_from_agent['symmetrical_key']

        self.connect_to_service_proxy()

        message_to_service = {
            'request': request,
            'request_code': request_code,
            'data': data
        }
        self.send_to_service_proxy(json.dumps(message_to_service))

        start_time = time.time()

        try:
            raw_message_from_service = self.receive_from_service_proxy()
            while raw_message_from_service is None:

                if time.time() - start_time > self.SERVICE_TIMEOUT:
                    self.disconnect_with_service()
                    return False

                raw_message_from_service = self.receive_from_service_proxy()
                time.sleep(0.001)

        except (ConnectionResetError, ConnectionAbortedError, socket.timeout):
            self.disconnect_with_service()
            return False

        message_from_service = json.loads(raw_message_from_service)

        if message_from_service['response_code'] == '999':
            response_from_service = message_from_service['data']
            message_to_client = {
                'request': 'communication',
                'request_code': '105',
                'response': response_from_service,
                'response_code': '999'
            }
            self.disconnect_with_service()
            self.send_to_client(json.dumps(message_to_client))
            return True
        else:
            return False

    def change_working_status(self, is_working):
        working_status = 'working' if is_working else 'not_working'
        self.working_status = is_working

        message_to_agent = {
            'request': 'command',
            'request_code': '103',
            'data': working_status
        }
        self.send_to_agent(message_to_agent)

    def read_from_agent(self):
        message_from_agent = self.receive_from_agent()
        if message_from_agent:
            if message_from_agent['request_code'] == '103':
                if message_from_agent['command'] == 'stop':
                    close_socket(self.api_gateway_socket)
                    self.stop_flag = True

    def communication_with_client(self):
        while not self.stop_flag:
            self.working_status = self.connect_with_client()

            if self.working_status:
                self.change_working_status(True)

                while self.working_status:
                    raw_message_from_client = self.receive_from_client()
                    while raw_message_from_client is None:
                        raw_message_from_client = self.receive_from_client()
                        time.sleep(0.001)

                    if raw_message_from_client == 'error':
                        continue

                    message_from_client = json.loads(raw_message_from_client)

                    if message_from_client['request_code'] == '105':
                        success_flag = self.communication_with_services(message_from_client)

                        number_of_attempts = 0

                        while success_flag is False and number_of_attempts < self.maximum_number_of_attempts:
                            success_flag = self.communication_with_services(message_from_client)
                            number_of_attempts += 1

                    elif message_from_client['request_code'] == '106':
                        self.disconnect_with_client()
                        self.change_working_status(False)

                    self.message_id += 1
            else:
                self.read_from_agent()
