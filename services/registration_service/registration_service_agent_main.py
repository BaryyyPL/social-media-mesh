import json
import queue
import socket
import threading
import time

import psutil

from cryptography_process import (
    load_or_create_private_key,
    create_public_key,
    load_manager_public_key,
    handshake_receiver,
    send_secure_message,
    receive_secure_message,
    base64_decode
)
from registration_service_sidecar_main import Service_Proxy
from registration_service_main import Service

minimal_number_of_working_workers = 1
maximum_number_of_not_working_workers = 1


def find_free_port():
    reserved_ports = [9999, 9998, 9997, 9996, 9995, 9994, 9993, 9992, 9991,  # services ports
                      8666, 8667, 8668, 8669, 8670  # api gateway ports
                      ]

    start_port = 1024
    end_port = 49151

    for port in range(start_port, end_port + 1):
        if port in reserved_ports:
            continue

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', port))

                return port
        except OSError:
            continue

    raise Exception("Nie znaleziono żadnego wolnego portu!")


def send_to_process(process, message):
    queue_to_worker = process['agent_queue_to_service_proxy']
    queue_to_worker.put(message)


def receive_from_process(process):
    queue_from_worker = process['agent_queue_from_service_proxy']
    try:
        return queue_from_worker.get_nowait()
    except queue.Empty:
        return None


def receive_status_from_process(process):
    queue_from_worker = process['status_queue']
    try:
        return queue_from_worker.get_nowait()
    except queue.Empty:
        return None


def stop_worker(process):
    queue_to_worker = process['agent_queue_to_service_proxy']
    message_to_service = {
        'request': 'command',
        'request_code': '103',
        'command': 'stop'
    }
    queue_to_worker.put(message_to_service)


class Service_Agent:
    def __init__(self):

        self.worker_lock = threading.Lock()
        self.flag = True
        self.message_id = 0
        self.manager_port = 9998
        self.manager_host = 'localhost'

        self.private_key = load_or_create_private_key()
        self.public_key = create_public_key(self.private_key)
        self.manager_public_key = load_manager_public_key()
        self.symmetrical_key = None

        self.manager_socket = self.connect_to_server()
        self.manager_socket.settimeout(0.1)
        self.list_of_service_workers = []

        self.database_host = None
        self.database_user = None
        self.database_password = None
        self.database_database = None
        self.database_port = None
        self.database_symmetrical_key = None

    def run(self):
        try:
            self.communication()

        except KeyboardInterrupt:
            print('Shutting down agent - interrupted by user')
            self.flag = False
            for p in self.list_of_service_workers:
                stop_worker(p)

        except (KeyboardInterrupt, ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
            print(f'Shutting down agent - {e}')
            self.flag = False
            for p in self.list_of_service_workers:
                stop_worker(p)

    def connect_to_server(self):
        manager_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        manager_socket.connect((self.manager_host, self.manager_port))
        self.symmetrical_key = handshake_receiver(
            self.public_key, self.private_key, self.manager_public_key, manager_socket
        )

        return manager_socket

    def receive_database_configuration(self):

        raw_message_from_agent = self.receive_from_manager()
        while raw_message_from_agent is None:
            raw_message_from_agent = self.receive_from_manager()
            time.sleep(0.001)

        message_from_agent = json.loads(raw_message_from_agent)

        if message_from_agent['request_code'] == '108':
            session_message_id = message_from_agent['message_id']
            database_configuration = message_from_agent['database_configuration']

            self.database_host = database_configuration['host']
            self.database_user = database_configuration['user']
            self.database_password = database_configuration['password']
            self.database_database = database_configuration['database']
            self.database_port = database_configuration['port']
            self.database_symmetrical_key = base64_decode(database_configuration['database_symmetrical_key'])

            message = {
                'request': 'database_configuration',
                'request_code': '108',
                'response_code': '999',
                'message_id': session_message_id
            }

            self.send_to_manager(json.dumps(message))

            return True

        raise SystemExit

    def create_worker(self):
        host = 'localhost'
        port = find_free_port()
        agent_queue_to_service_proxy = queue.Queue()
        agent_queue_from_service_proxy = queue.Queue()
        service_proxy_queue_to_service = queue.Queue()
        service_proxy_queue_from_service = queue.Queue()
        status_queue = queue.Queue()

        service_proxy = Service_Proxy(
            host, port,
            agent_queue_to_service_proxy,
            agent_queue_from_service_proxy,
            service_proxy_queue_to_service,
            service_proxy_queue_from_service,
            status_queue
        )
        service = Service(service_proxy_queue_to_service,
                          service_proxy_queue_from_service,
                          self.database_host, self.database_user,
                          self.database_password, self.database_database,
                          self.database_port, self.database_symmetrical_key
                          )

        return {
            'service_proxy': service_proxy,
            'service': service,
            'host': host,
            'port': port,
            'agent_queue_to_service_proxy': agent_queue_to_service_proxy,
            'agent_queue_from_service_proxy': agent_queue_from_service_proxy,
            'status_queue': status_queue,
            'is_working': False
        }

    def send_to_manager(self, message):
        send_secure_message(self.manager_socket, self.symmetrical_key, message)

    def receive_from_manager(self):
        received_secure_message = receive_secure_message(self.manager_socket, self.symmetrical_key)
        if received_secure_message:
            return received_secure_message.decode()
        else:
            return None

    def find_not_working_worker(self):
        with self.worker_lock:
            list_of_service_workers_copy = self.list_of_service_workers.copy()

        service_proxy = None
        host = None
        port = None

        for worker in list_of_service_workers_copy:
            if worker['is_working'] is False:
                service_proxy = worker
                host = worker['host']
                port = worker['port']
        return service_proxy, host, port

    def hardware_load_check(self):
        cpu = psutil.cpu_percent(interval=0)
        memory = psutil.virtual_memory()
        load = (cpu + memory.percent) / 2

        message_to_manager = {
            'request': 'load',
            'request_code': '107',
            'load': load
        }
        self.send_to_manager(json.dumps(message_to_manager))

    def manage_workers(self):
        while self.flag:
            with self.worker_lock:
                list_of_service_workers_copy = self.list_of_service_workers.copy()

            working_count = len(list(filter(lambda w: w['is_working'], list_of_service_workers_copy)))
            number_of_workers = len(list_of_service_workers_copy)

            if working_count == number_of_workers:
                list_of_service_workers_copy.append(self.create_worker())
                with self.worker_lock:
                    self.list_of_service_workers[:] = list_of_service_workers_copy

            not_working_workers_list = [w for w in list_of_service_workers_copy if not w['is_working']]
            numbers_of_workers_to_terminate = len(not_working_workers_list) - maximum_number_of_not_working_workers

            if numbers_of_workers_to_terminate > 0:
                for w in not_working_workers_list[:numbers_of_workers_to_terminate]:
                    stop_worker(w)
                    list_of_service_workers_copy.remove(w)
                    with self.worker_lock:
                        self.list_of_service_workers[:] = list_of_service_workers_copy

            time.sleep(0.001)

    def read_service_working_status(self):
        while self.flag:
            with self.worker_lock:
                list_of_service_workers_copy = self.list_of_service_workers.copy()

            for p in list_of_service_workers_copy:
                working_status = receive_status_from_process(p)
                if working_status and working_status['request_code'] == '103':
                    if working_status['data'] == 'working':
                        p['is_working'] = True
                    else:
                        p['is_working'] = False
                    with self.worker_lock:
                        self.list_of_service_workers[:] = list_of_service_workers_copy
            time.sleep(0.001)

    def communication(self):

        self.receive_database_configuration()

        with self.worker_lock:
            for _ in range(minimal_number_of_working_workers):
                self.list_of_service_workers.append(self.create_worker())

        threading.Thread(target=self.read_service_working_status, daemon=True).start()
        threading.Thread(target=self.manage_workers, daemon=True).start()

        print('Working...')

        last_report_time = time.monotonic()

        while self.flag:

            raw_message_from_manager = self.receive_from_manager()
            if raw_message_from_manager is None:

                if time.monotonic() - last_report_time > 10:
                    self.hardware_load_check()
                    last_report_time = time.monotonic()

                continue

            message_from_manager = json.loads(raw_message_from_manager)

            if message_from_manager['request_code'] == '104':
                session_message_id = message_from_manager['message_id']
                service_proxy, host, port = self.find_not_working_worker()
                while service_proxy is None:
                    service_proxy, host, port = self.find_not_working_worker()
                    time.sleep(0.001)

                message_to_manager = {
                    'request': 'ask_for_service_info',
                    'request_code': '104',
                    'host': host,
                    'port': port,
                    'message_id': session_message_id,
                    'response_code': '999'
                }
                self.send_to_manager(json.dumps(message_to_manager))

                raw_message_from_manager = self.receive_from_manager()
                if raw_message_from_manager is None:
                    return None

                message_from_manager = json.loads(raw_message_from_manager)

                if message_from_manager['request_code'] == '102' and message_from_manager[
                    'message_id'] == session_message_id:
                    encoded_symmetrical_key = message_from_manager['symmetrical_key']
                    symmetrical_key = base64_decode(encoded_symmetrical_key)

                    message_to_service_proxy = {
                        'request': 'provide_service_info',
                        'request_code': '102',
                        'symmetrical_key': symmetrical_key,
                    }
                    send_to_process(service_proxy, message_to_service_proxy)

                message_from_process = receive_from_process(service_proxy)
                while message_from_process is None:
                    message_from_process = receive_from_process(service_proxy)
                    time.sleep(0.001)

                if message_from_process['request_code'] == '102' and message_from_process['message'] == 'Server OK':
                    message_to_manager = {
                        'request': 'provide_service_info',
                        'request_code': '102',
                        'message': 'Server OK'
                    }
                elif message_from_process['request_code'] == '102' and message_from_process[
                    'message'] == 'Server not OK':
                    message_to_manager = {
                        'request': 'provide_service_info',
                        'request_code': '102',
                        'message': 'Server not OK'
                    }

                self.send_to_manager(json.dumps(message_to_manager))

            time.sleep(0.001)


agent = Service_Agent()
agent.run()
