import json
import socket
import threading
import time

from cryptography_process import (
    load_private_key,
    handshake_sender,
    send_secure_message,
    receive_secure_message,
    generate_symmetrical_key,
    base64_encode
)

from database_configuration import Database

lock = threading.Lock()


class Manager:
    def __init__(self):

        self.flag = True
        self.port_for_service_agent = 9999
        self.port_for_api_gateway_agent = 9998
        self.host = 'localhost'

        self.maximum_number_of_attempts = 3

        with lock:
            self.list_of_api_gateways = []
            self.list_of_service = []
            self.message_id = 0

        self.api_gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.private_key = load_private_key()

        self.database_configuration = Database.to_dict()

        self.timeout = 1

        self.heartbeat_timeout = 60

    def run(self):
        try:
            threading.Thread(target=self.connect_with_api_gateway_agents, daemon=True).start()
            threading.Thread(target=self.connect_with_api_service_agents, daemon=True).start()
            self.start_communication()
        except KeyboardInterrupt:
            print('Execution interrupted by user.')
            self.cleanup_sockets()
        except (OSError, ConnectionResetError, BrokenPipeError) as e:
            print(f'Connection error: {e}')
            self.cleanup_sockets()
        except Exception as e:
            print(f'Unexpected error: {e}')
            self.cleanup_sockets()

    def cleanup_sockets(self):
        self.api_gateway_socket.close()
        self.service_socket.close()

        with lock:
            for agent in self.list_of_api_gateways:
                agent['socket'].close()
            for agent in self.list_of_service:
                agent['socket'].close()

        self.flag = False
        print('All sockets closed, Manager terminated.')

    def connect_with_api_gateway_agents(self):

        self.api_gateway_socket.bind((self.host, self.port_for_api_gateway_agent))
        self.api_gateway_socket.listen(5)

        while True and self.flag:
            try:
                api_gateway_agent_socket, api_gateway_agent_address = self.api_gateway_socket.accept()
            except OSError:
                break

            with lock:
                session_message_id = self.message_id
                self.message_id += 1

            agent_public_key, symmetrical_key = handshake_sender(
                self.private_key,
                api_gateway_agent_socket,
                session_message_id
            )

            if agent_public_key and symmetrical_key:
                agent = {
                    'socket': api_gateway_agent_socket,
                    'public_key': agent_public_key,
                    'symmetrical_key': symmetrical_key,
                    'load': 100,
                    'last_time_report': time.monotonic()
                }
                api_gateway_agent_socket.settimeout(self.timeout)
                with lock:
                    self.list_of_api_gateways.append(agent)
            else:
                api_gateway_agent_socket.close()
        self.api_gateway_socket.close()

    def connect_with_api_service_agents(self):

        self.service_socket.bind((self.host, self.port_for_service_agent))
        self.service_socket.listen(5)

        while True and self.flag:
            try:
                service_agent_socket, service_agent_address = self.service_socket.accept()
            except OSError:
                break

            with lock:
                session_message_id = self.message_id
                self.message_id += 1

            agent_public_key, symmetrical_key = handshake_sender(
                self.private_key,
                service_agent_socket,
                session_message_id
            )

            if agent_public_key and symmetrical_key:
                agent = {
                    'socket': service_agent_socket,
                    'public_key': agent_public_key,
                    'symmetrical_key': symmetrical_key,
                    'load': 100,
                    'last_time_report': time.monotonic()
                }

                if self.send_database_configuration(agent):

                    service_agent_socket.settimeout(self.timeout)
                    with lock:
                        self.list_of_service.append(agent)

                else:
                    service_agent_socket.close()

            else:
                service_agent_socket.close()
        self.service_socket.close()

    def send_database_configuration(self, service_agent):

        with lock:
            session_message_id = self.message_id
            self.message_id += 1


        message = {
            'request': 'database_configuration',
            'request_code': '108',
            'database_configuration': self.database_configuration,
            'message_id': session_message_id
        }

        self.send_message(service_agent, json.dumps(message))

        start_time = time.monotonic()
        timeout_flag = False

        raw_response_from_service_agent = self.receive_message(service_agent)
        while raw_response_from_service_agent is None and timeout_flag is False:
            raw_response_from_service_agent = self.receive_message(service_agent)
            time.sleep(0.001)
            if time.monotonic() - start_time > 10:
                timeout_flag = True

        if timeout_flag is True:
            return False

        response_from_service_agent = json.loads(raw_response_from_service_agent)

        if (response_from_service_agent['request_code'] == '108'
                and response_from_service_agent['response_code'] == '999'
                and response_from_service_agent['message_id'] == session_message_id):
            return True

        return False

    def start_communication(self):

        success_flag = False
        while not success_flag:
            with lock:
                ready = len(self.list_of_service) > 0 and len(self.list_of_api_gateways) > 0

            if ready:
                print('Working...')
                success_flag = True
                self.communication()
                return

            time.sleep(0.001)

    def do_cleanup(self, agent):
        with lock:
            if agent in self.list_of_api_gateways:
                self.list_of_api_gateways.remove(agent)
            if agent in self.list_of_service:
                self.list_of_service.remove(agent)

    def send_message(self, agent, message):
        send_secure_message(agent['socket'], agent['symmetrical_key'], message)

    def receive_message(self, agent):
        try:
            data = receive_secure_message(agent['socket'], agent['symmetrical_key'])
            if data is None:
                return None
            return data.decode()

        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            return None

    def sort_agents(self):
        with lock:
            self.list_of_service.sort(key=lambda agent: agent['load'])

    def request_service_info(self, agent, session_message_id):

        message = {
            'request': 'ask_for_service_info',
            'request_code': '104',
            'message_id': session_message_id
        }

        self.send_message(agent, json.dumps(message))

        raw_response = self.receive_message(agent)
        if not raw_response:
            return None

        response = json.loads(raw_response)

        if (
            response['response_code'] == '999'
            and response['request_code'] == '104'
            and response['message_id'] == session_message_id
        ):
            return response['host'], response['port'], agent

        return None

    def change_agent_load(self, agent, load_message):
        new_load = int(load_message['load'])

        with lock:
            for a in self.list_of_service:
                if a['socket'] == agent['socket']:
                    a['load'] = new_load
                    break

        self.sort_agents()

    def receive_load_from_service(self):

        now = time.monotonic()

        service_agents = list(self.list_of_service)

        for service_agent in service_agents:
            service_message_data = self.receive_message(service_agent)
            if service_message_data is None:
                if now - service_agent['last_time_report'] > self.heartbeat_timeout:
                    self.do_cleanup(service_agent)
                continue

            service_agent['last_time_report'] = now
            message_from_agent = json.loads(service_message_data)
            self.change_agent_load(service_agent, message_from_agent)

    def handle_service_request(self):

        with lock:
            api_gateways = self.list_of_api_gateways.copy()

        now = time.monotonic()

        for api_gateway_agent in api_gateways:
            message_data = self.receive_message(api_gateway_agent)

            if message_data is None:
                if now - api_gateway_agent['last_time_report'] > self.heartbeat_timeout:
                    self.do_cleanup(api_gateway_agent)
                continue

            api_gateway_agent['last_time_report'] = now

            message_from_agent = json.loads(message_data)

            if message_from_agent['request_code'] == '104':

                session_message_id = message_from_agent['message_id']
                service_type = message_from_agent['service_type']

                if service_type == 'service':
                    success_flag = False
                    number_of_attempts = 0

                    while not success_flag and number_of_attempts < self.maximum_number_of_attempts:

                        result = self.request_service_info(self.list_of_service[0], session_message_id)

                        if result:
                            success_flag = True
                            host, port, service_agent = result

                            symmetrical_key = generate_symmetrical_key()

                            message = {
                                'request': 'provide_service_info',
                                'request_code': '102',
                                'symmetrical_key': base64_encode(symmetrical_key),
                                'message_id': session_message_id
                            }

                            self.send_message(service_agent, json.dumps(message))

                            raw_response = None
                            while raw_response is None:
                                raw_response = self.receive_message(service_agent)
                                time.sleep(0.001)

                            response_from_service = json.loads(raw_response)

                            if response_from_service['message'] == 'Server OK':
                                response = {
                                    'request': 'provide_service_info',
                                    'request_code': '102',
                                    'host': host,
                                    'port': port,
                                    'symmetrical_key': base64_encode(symmetrical_key),
                                    'message_id': session_message_id,
                                    'response_code': '999'
                                }
                            else:
                                response = {
                                    'request': 'provide_service_info',
                                    'request_code': '102',
                                    'message_id': session_message_id,
                                    'response_code': '998'
                                }

                            self.send_message(api_gateway_agent, json.dumps(response))
                        else:
                            number_of_attempts += 1

    def communication(self):
        while self.flag:
            self.handle_service_request()
            self.receive_load_from_service()
            if not self.list_of_service:
                print('No agents of any type available — shutting down manager')
                raise SystemExit

            time.sleep(0.001)


manager = Manager()
manager.run()
