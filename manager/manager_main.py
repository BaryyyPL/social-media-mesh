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


def receive_message(agent):
    try:
        data = receive_secure_message(agent['socket'], agent['symmetrical_key'])
        if data is None:
            return None
        return data.decode()

    except (ConnectionResetError, BrokenPipeError, OSError):
        return None


def send_message(agent, message):
    send_secure_message(agent['socket'], agent['symmetrical_key'], message)


def do_cleanup(agent, agent_list):
    with lock:
        if agent in agent_list:
            agent_list.remove(agent)


def request_service_info(agent, session_message_id):
    message = {
        'request': 'ask_for_service_info',
        'request_code': '104',
        'message_id': session_message_id
    }

    send_message(agent, json.dumps(message))

    raw_response = receive_message(agent)
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


def sort_agents(agent_list):
    with lock:
        agent_list.sort(key=lambda agent: agent['load'])


def change_agent_load(agent, load_message, agent_list):
    new_load = int(load_message['load'])

    with lock:
        for a in agent_list:
            if a['socket'] == agent['socket']:
                a['load'] = new_load
                break

    sort_agents(agent_list)


class Manager:
    def __init__(self):

        self.flag = True
        self.port_for_api_gateway_agent = 9999
        self.port_for_registration_service_agent = 9998
        self.port_for_login_service_agent = 9997
        self.port_for_upload_posts_service_agent = 9996
        self.port_for_read_posts_service_agent = 9995
        self.port_for_upload_files_service_agent = 9994
        self.port_for_download_files_service_agent = 9993
        self.port_for_available_files_service_agent = 9992
        self.port_for_delete_account_service_agent = 9991
        self.host = 'localhost'

        self.maximum_number_of_attempts = 3

        with lock:
            self.list_of_api_gateways = []
            self.list_of_registration_services = []
            self.list_of_login_services = []
            self.list_of_upload_posts_services = []
            self.list_of_read_posts_services = []
            self.list_of_upload_files_services = []
            self.list_of_download_files_services = []
            self.list_of_available_files_service = []
            self.list_of_delete_account_service = []
            self.message_id = 0

        self.api_gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.registration_service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.login_service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.upload_posts_service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.read_posts_service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.upload_files_service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.download_files_service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.available_files_service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.delete_account_service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.list_of_service_sockets = [self.api_gateway_socket, self.registration_service_socket,
                                   self.login_service_socket, self.upload_posts_service_socket,
                                   self.read_posts_service_socket, self.upload_files_service_socket,
                                   self.download_files_service_socket, self.available_files_service_socket,
                                   self.delete_account_service_socket]

        self.list_of_lists_of_agents = [self.list_of_api_gateways, self.list_of_registration_services,
                                   self.list_of_login_services, self.list_of_upload_posts_services,
                                   self.list_of_read_posts_services, self.list_of_upload_files_services,
                                   self.list_of_download_files_services, self.list_of_available_files_service,
                                   self.list_of_delete_account_service]

        self.private_key = load_private_key()

        self.database_configuration = Database.to_dict()

        self.timeout = 1

        self.heartbeat_timeout = 60

    def run(self):
        try:
            api_gateway_thread = threading.Thread(
                target=self.connect_with_agents,
                args=(
                    self.port_for_api_gateway_agent,
                    self.list_of_api_gateways,
                    self.api_gateway_socket),
                daemon=True)
            registration_service_thread = threading.Thread(
                target=self.connect_with_agents,
                args=(
                    self.port_for_registration_service_agent,
                    self.list_of_registration_services,
                    self.registration_service_socket),
                daemon=True)
            login_service_thread = threading.Thread(
                target=self.connect_with_agents,
                args=(
                    self.port_for_login_service_agent,
                    self.list_of_login_services,
                    self.login_service_socket),
                daemon=True)
            upload_posts_service_thread = threading.Thread(
                target=self.connect_with_agents,
                args=(
                    self.port_for_upload_posts_service_agent,
                    self.list_of_upload_posts_services,
                    self.upload_posts_service_socket),
                daemon=True)
            read_posts_service_thread = threading.Thread(
                target=self.connect_with_agents,
                args=(
                    self.port_for_read_posts_service_agent,
                    self.list_of_read_posts_services,
                    self.read_posts_service_socket),
                daemon=True)
            upload_files_service_thread = threading.Thread(
                target=self.connect_with_agents,
                args=(
                    self.port_for_upload_files_service_agent,
                    self.list_of_upload_files_services,
                    self.upload_files_service_socket),
                daemon=True)
            download_files_service_thread = threading.Thread(
                target=self.connect_with_agents,
                args=(
                    self.port_for_download_files_service_agent,
                    self.list_of_download_files_services,
                    self.download_files_service_socket),
                daemon=True)

            available_files_service_thread = threading.Thread(
                target=self.connect_with_agents,
                args=(
                    self.port_for_available_files_service_agent,
                    self.list_of_available_files_service,
                    self.available_files_service_socket),
                daemon=True)

            delete_account_service_thread = threading.Thread(
                target=self.connect_with_agents,
                args=(
                    self.port_for_delete_account_service_agent,
                    self.list_of_delete_account_service,
                    self.delete_account_service_socket),
                daemon=True)

            api_gateway_thread.start()
            #registration_service_thread.start()
            #login_service_thread.start()
            upload_posts_service_thread.start()
            read_posts_service_thread.start()
            #upload_files_service_thread.start()
            #download_files_service_thread.start()
            #available_files_service_thread.start()
            #delete_account_service_thread.start()

            print('Threads running...')
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

        for service_socket in self.list_of_service_sockets:
            service_socket.close()

        with lock:
            for list_of_agents in self.list_of_lists_of_agents:
                for agent in list_of_agents:
                    agent['socket'].close()

        self.flag = False
        print('All sockets closed, Manager terminated.')

    def connect_with_agents(self, port, agent_list, service_socket):

        service_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        service_socket.bind((self.host, port))
        service_socket.listen(5)

        while True and self.flag:
            try:
                agent_socket, agent_address = service_socket.accept()
            except OSError:
                break

            with lock:
                session_message_id = self.message_id
                self.message_id += 1

            agent_public_key, symmetrical_key = handshake_sender(
                self.private_key,
                agent_socket,
                session_message_id
            )

            if agent_public_key and symmetrical_key:
                agent = {
                    'socket': agent_socket,
                    'public_key': agent_public_key,
                    'symmetrical_key': symmetrical_key,
                    'load': 100,
                    'last_time_report': time.monotonic()
                }

                if service_socket is self.api_gateway_socket:

                    agent_socket.settimeout(self.timeout)
                    with lock:
                        agent_list.append(agent)

                else:

                    if self.send_database_configuration(agent):

                        agent_socket.settimeout(self.timeout)
                        with lock:
                            agent_list.append(agent)

                    else:
                        agent_socket.close()

            else:
                agent_socket.close()
        service_socket.close()

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

        send_message(service_agent, json.dumps(message))

        start_time = time.monotonic()
        timeout_flag = False

        raw_response_from_service_agent = receive_message(service_agent)
        while raw_response_from_service_agent is None and timeout_flag is False:
            raw_response_from_service_agent = receive_message(service_agent)
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

    def verify_agents(self):
        with lock:
            #lists = self.list_of_lists_of_agents
            lists = [self.list_of_api_gateways,
                     #self.list_of_registration_services,
                     #self.list_of_login_services,
                     self.list_of_upload_posts_services,
                     self.list_of_read_posts_services,
                     #self.list_of_upload_files_services,
                     #self.list_of_download_files_services,
                     #self.list_of_available_files_service,
                     #self.list_of_delete_account_service
            ]

        for list_of_agents in lists:
            if not list_of_agents:
                return False
        return True

    def start_communication(self):

        success_flag = False
        while not success_flag:

            if self.verify_agents():
                print('Working...')
                self.communication()
                return

            time.sleep(0.001)

    def receive_load_from_service(self):

        now = time.monotonic()

        agents_lists = [self.list_of_registration_services, self.list_of_login_services,
                        self.list_of_upload_posts_services, self.list_of_read_posts_services,
                        self.list_of_upload_files_services, self.list_of_download_files_services,
                        self.list_of_available_files_service]

        for a_list in agents_lists:

            service_agents = list(a_list)

            for service_agent in service_agents:
                service_message_data = receive_message(service_agent)
                if service_message_data is None:
                    if now - service_agent['last_time_report'] > self.heartbeat_timeout:
                        do_cleanup(service_agent, a_list)
                    continue

                service_agent['last_time_report'] = now
                message_from_agent = json.loads(service_message_data)
                change_agent_load(service_agent, message_from_agent, a_list)

    def handle_service_request(self):

        with lock:
            api_gateways = self.list_of_api_gateways.copy()

        now = time.monotonic()

        for api_gateway_agent in api_gateways:
            message_data = receive_message(api_gateway_agent)

            if message_data is None:
                if now - api_gateway_agent['last_time_report'] > self.heartbeat_timeout:
                    do_cleanup(api_gateway_agent, self.list_of_api_gateways)
                continue

            api_gateway_agent['last_time_report'] = now

            message_from_agent = json.loads(message_data)

            if message_from_agent['request_code'] == '104':

                session_message_id = message_from_agent['message_id']
                service_type = message_from_agent['service_type']

                agent_list = []

                match service_type:
                    case 'registration_service':
                        agent_list = self.list_of_registration_services

                    case 'login_service':
                        agent_list = self.list_of_login_services

                    case 'upload_posts_service':
                        agent_list = self.list_of_upload_posts_services

                    case 'read_posts_service':
                        agent_list = self.list_of_read_posts_services

                    case 'upload_files_service':
                        agent_list = self.list_of_upload_files_services

                    case 'download_files_service':
                        agent_list = self.list_of_download_files_services

                success_flag = False
                number_of_attempts = 0

                while not success_flag and number_of_attempts < self.maximum_number_of_attempts:

                    result = request_service_info(agent_list[0], session_message_id)

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

                        send_message(service_agent, json.dumps(message))

                        raw_response = None
                        while raw_response is None:
                            raw_response = receive_message(service_agent)
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

                        send_message(api_gateway_agent, json.dumps(response))
                    else:
                        number_of_attempts += 1

    def communication(self):
        while self.flag:
            self.handle_service_request()
            self.receive_load_from_service()
            if not self.verify_agents():
                print('No agents of any type available — shutting down manager')
                raise SystemExit

            time.sleep(0.001)


manager = Manager()
manager.run()
