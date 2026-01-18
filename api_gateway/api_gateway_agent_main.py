import json
import queue
import socket
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
from api_gateway_main import API_Gateway

minimal_number_of_working_workers = 5
maximum_number_of_not_working_workers = 5
list_of_ports_for_api_gateway = [8666, 8667, 8668, 8669, 8670]


def create_worker():
    host = '127.0.0.1'
    port = list_of_ports_for_api_gateway.pop()
    queue_to_worker = queue.Queue()
    queue_from_worker = queue.Queue()
    worker = API_Gateway(host, port, queue_to_worker, queue_from_worker)
    return {
        'worker': worker,
        'host': host,
        'port': port,
        'queue_to_worker': queue_to_worker,
        'queue_from_worker': queue_from_worker,
        'is_working': False
    }


def send_to_process(process, message):
    queue_to_worker = process['queue_to_worker']
    queue_to_worker.put(message)


def receive_from_process(process):
    queue_from_worker = process['queue_from_worker']
    try:
        return queue_from_worker.get_nowait()
    except queue.Empty:
        return None


def stop_worker(process):
    queue_to_worker = process['queue_to_worker']
    port = process['port']
    message_to_service = {
        'request': 'command',
        'request_code': '103',
        'command': 'stop'
    }
    queue_to_worker.put(message_to_service)
    list_of_ports_for_api_gateway.append(port)


def change_working_status(api_gateway_worker, message_from_api_gateway):
    command = message_from_api_gateway['data']
    if command == 'working':
        api_gateway_worker['is_working'] = True
    elif command == 'not_working':
        api_gateway_worker['is_working'] = False


class API_Gateway_Agent:
    def __init__(self):

        self.flag = True
        self.message_id = 0
        self.manager_port = 9999
        self.manager_host = '127.0.0.1'
        self.private_key = load_or_create_private_key()
        self.public_key = create_public_key(self.private_key)
        self.manager_public_key = load_manager_public_key()
        self.symmetrical_key = None
        self.manager_socket = self.connect_to_server()
        self.list_of_api_gateway_workers = []

    def run(self):
        try:
            self.communication()

        except KeyboardInterrupt:
            print('Shutting down agent - interrupted by user')
            self.flag = False
            for p in self.list_of_api_gateway_workers:
                stop_worker(p)

        except (KeyboardInterrupt, ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
            print(f'Shutting down agent - {e}')
            self.flag = False
            for p in self.list_of_api_gateway_workers:
                stop_worker(p)

    def connect_to_server(self):
        manager_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        manager_socket.connect((self.manager_host, self.manager_port))
        self.symmetrical_key = handshake_receiver(
            self.public_key,
            self.private_key,
            self.manager_public_key,
            manager_socket
        )
        return manager_socket

    def send_to_manager(self, message):
        send_secure_message(self.manager_socket, self.symmetrical_key, message)

    def receive_from_manager(self):
        received_from_process = receive_secure_message(self.manager_socket, self.symmetrical_key)
        if received_from_process:
            return received_from_process.decode()
        else:
            return None

    def ask_for_service(self, session_message_id, api_gateway_worker, message_from_api_gateway):
        service_type = message_from_api_gateway['service_type']
        message_to_manager = {
            'request': 'ask_for_service',
            'request_code': '104',
            'service_type': service_type,
            'message_id': session_message_id
        }
        self.send_to_manager(json.dumps(message_to_manager))

        raw_response_from_manager = self.receive_from_manager()
        while not raw_response_from_manager:
            raw_response_from_manager = self.receive_from_manager()
            time.sleep(0.001)

        response_from_manager = json.loads(raw_response_from_manager)

        if (response_from_manager['response_code'] == '999' and
                response_from_manager['request_code'] == '102' and
                response_from_manager['message_id'] == session_message_id):

            host = response_from_manager['host']
            port = response_from_manager['port']
            encoded_symmetrical_key = response_from_manager['symmetrical_key']
            symmetrical_key = base64_decode(encoded_symmetrical_key)

            message_to_api_gateway = {
                'request': 'communication',
                'request_code': '105',
                'service_type': service_type,
                'host': host,
                'port': port,
                'symmetrical_key': symmetrical_key,
                'response_code': '999'
            }

            send_to_process(api_gateway_worker, message_to_api_gateway)

    def manage_workers(self):
        working_count = len(list(filter(lambda w: w['is_working'], self.list_of_api_gateway_workers)))
        number_of_workers = len(self.list_of_api_gateway_workers)
        if working_count == number_of_workers:
            self.list_of_api_gateway_workers.append(create_worker())

        not_working_workers_list = [w for w in self.list_of_api_gateway_workers if not w['is_working']]
        numbers_of_workers_to_terminate = len(not_working_workers_list) - maximum_number_of_not_working_workers
        if numbers_of_workers_to_terminate > 0:
            for w in not_working_workers_list[:numbers_of_workers_to_terminate]:
                stop_worker(w)
                self.list_of_api_gateway_workers.remove(w)

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

    def communication(self):
        for i in range(minimal_number_of_working_workers):
            self.list_of_api_gateway_workers.append(create_worker())

        last_report_time = time.monotonic()

        print('Working...')

        while self.flag:
            self.manage_workers()

            for api_gateway_worker in self.list_of_api_gateway_workers:
                message_from_api_gateway = receive_from_process(api_gateway_worker)
                if message_from_api_gateway is None:

                    if time.monotonic() - last_report_time >= 10:
                        self.hardware_load_check()
                        last_report_time = time.monotonic()

                    continue

                session_message_id = self.message_id

                if message_from_api_gateway['request_code'] == '105':
                    self.ask_for_service(session_message_id, api_gateway_worker, message_from_api_gateway)
                elif message_from_api_gateway['request_code'] == '103':
                    change_working_status(api_gateway_worker, message_from_api_gateway)

                self.message_id += 1

            time.sleep(0.001)


agent = API_Gateway_Agent()
agent.run()
