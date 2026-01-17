import json
import queue
import socket
import threading
import time

from cryptography_process import (send_secure_message, receive_secure_message, close_socket)

class Service_Proxy:
    def __init__(self, host, port, agent_queue_to_service_proxy, agent_queue_from_service_proxy,
                 service_proxy_queue_to_service, service_proxy_queue_from_service, status_queue):

        self.working_status = False
        # Starting of server
        self.host = host
        self.port = port
        self.service_proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.service_proxy_socket.bind((self.host, self.port))
        self.service_proxy_socket.listen(5)
        self.service_proxy_socket.settimeout(10)

        self.api_gateway_socket = None
        self.api_gateway_address = None
        self.symmetrical_key = None

        self.agent_queue_to_service_proxy = agent_queue_to_service_proxy
        self.agent_queue_from_service_proxy = agent_queue_from_service_proxy

        self.service_proxy_queue_to_service = service_proxy_queue_to_service
        self.service_proxy_queue_from_service = service_proxy_queue_from_service

        self.status_queue = status_queue

        self.stop_flag = False
        self.thread = threading.Thread(target=self.communication_with_api_gateway, daemon=True)
        self.thread.start()

    def start_server(self):
        try:
            self.service_proxy_socket.getsockname()
            return True
        except OSError:
            return False

    def connect_with_api_gateway(self):

        try:
            self.api_gateway_socket, self.api_gateway_address = self.service_proxy_socket.accept()
            return True
        except socket.timeout:
            return False


    def send_to_agent(self, message):
        self.agent_queue_from_service_proxy.put(message)

    def receive_from_agent(self):
        try:
            return self.agent_queue_to_service_proxy.get()
        except queue.Empty:
            return None

    def send_to_service(self, message):
        self.service_proxy_queue_to_service.put(message)

    def receive_from_service(self):
        return self.service_proxy_queue_from_service.get()

    def send_status_to_agent(self, message):
        self.status_queue.put(message)

    def send_to_api_gateway(self, message):
        send_secure_message(self.api_gateway_socket, self.symmetrical_key, message)

    def receive_from_api_gateway(self):
        try:
            received_secure_message = receive_secure_message(self.api_gateway_socket, self.symmetrical_key)
            if received_secure_message:
                return received_secure_message.decode()
            else:
                return None
        except (ConnectionResetError,  BrokenPipeError, OSError):
            self.disconnect_with_api_gateway()
            return 'error'

    def disconnect_with_api_gateway(self):
        close_socket(self.api_gateway_socket)
        self.api_gateway_socket = None
        self.api_gateway_address = None
        self.symmetrical_key = None
        self.change_working_status(False)

    def change_working_status(self, is_working):
        working_status = 'working' if is_working else 'not_working'
        self.working_status = is_working
        message_to_agent = {
            'request': 'command',
            'request_code': '103',
            'data': working_status
        }
        self.send_status_to_agent(message_to_agent)

    def communication_with_api_gateway(self):

        while not self.stop_flag:
            message_from_agent = self.receive_from_agent()

            while message_from_agent is None:
                message_from_agent = self.receive_from_agent()
                time.sleep(0.001)

            if message_from_agent['request_code'] == '103':
                if message_from_agent['command'] == 'stop':
                    message_to_service = {
                        'request': 'command',
                        'request_code': '103',
                        'command': 'stop'
                    }

                    self.send_to_service(message_to_service)
                    self.stop_flag = True
                    close_socket(self.service_proxy_socket)
            if message_from_agent['request_code'] == '102':
                self.symmetrical_key = message_from_agent['symmetrical_key']

                status = self.start_server()

                if status:
                    message_to_agent = {
                        'request': 'provide_service_info',
                        'request_code': '102',
                        'message': 'Server OK'
                    }

                else:
                    message_to_agent = {
                        'request': 'provide_service_info',
                        'request_code': '102',
                        'message': 'Server not OK'
                    }
                self.send_to_agent(message_to_agent)

                self.working_status = self.connect_with_api_gateway()
                if self.working_status:
                    self.change_working_status(True)

                    raw_message_from_api_gateway = self.receive_from_api_gateway()
                    while not raw_message_from_api_gateway:
                        raw_message_from_api_gateway = self.receive_from_api_gateway()
                        time.sleep(0.001)

                    if raw_message_from_api_gateway == 'error':
                        continue

                    message_from_api_gateway = json.loads(raw_message_from_api_gateway)

                    if message_from_api_gateway['request_code'] == '115':

                        data = message_from_api_gateway['data']

                        message_to_service = {
                            'request': 'available_files',
                            'request_code': '115',
                            'data': data
                        }

                        self.send_to_service(message_to_service)

                        response_from_service = self.receive_from_service()

                        data = response_from_service['data']

                        message_to_api_gateway = {
                            'request': 'available_files',
                            'request_code': '115',
                            'data': data,
                            'response_code': '999'
                        }

                        self.send_to_api_gateway(json.dumps(message_to_api_gateway))

                        raw_message_from_api_gateway = self.receive_from_api_gateway()
                        while not raw_message_from_api_gateway:
                            raw_message_from_api_gateway = self.receive_from_api_gateway()
                            time.sleep(0.001)

                        if raw_message_from_api_gateway == 'error':
                            continue

                        message_from_api_gateway = json.loads(raw_message_from_api_gateway)

                        if message_from_api_gateway['request_code'] == '106':
                            self.disconnect_with_api_gateway()
