import queue
import threading
import time

import mysql.connector
from mysql.connector import Error

from cryptography_process import verify_password


class Service:
    def __init__(self, service_proxy_queue_to_service, service_proxy_queue_from_service,
                 database_host, database_user, database_password, database_database, database_port, database_symmetrical_key):

        self.service_proxy_queue_to_service = service_proxy_queue_to_service
        self.service_proxy_queue_from_service = service_proxy_queue_from_service

        self.database_host = database_host
        self.database_user = database_user
        self.database_password = database_password
        self.database_database = database_database
        self.database_port = database_port
        self.database_symmetrical_key = database_symmetrical_key

        self.db_connection = self.connect_to_database()
        if not self.db_connection:
            raise SystemExit("Cannot connect to database")

        self.cursor = self.db_connection.cursor(buffered=True, dictionary=True)

        self.stop_flag = False
        self.thread = threading.Thread(
            target=self.communication_with_service_proxy,
            daemon=True
        )
        self.thread.start()

    def send_to_service_proxy(self, message):
        self.service_proxy_queue_from_service.put(message)

    def receive_from_service_proxy(self):
        try:
            return self.service_proxy_queue_to_service.get_nowait()
        except queue.Empty:
            return None

    def connect_to_database(self):
        try:
            connection = mysql.connector.connect(
                host=self.database_host,
                user=self.database_user,
                password=self.database_password,
                database=self.database_database,
                port=self.database_port
            )

            if connection.is_connected():
                print("Database connected")
                return connection

        except Error as e:
            print(f"Database connection error: {e}")

        return None

    def communication_with_service_proxy(self):

        while not self.stop_flag:

            message_from_service_proxy = self.receive_from_service_proxy()
            while message_from_service_proxy is None:
                message_from_service_proxy = self.receive_from_service_proxy()
                time.sleep(0.001)

            if message_from_service_proxy['request_code'] == '110':

                data = message_from_service_proxy['data']

                login = data['login']

                response = {
                    'message': None,
                    'id': False
                }

                try:
                    self.cursor.execute(
                        "SELECT id, password_hash, is_deleted FROM users WHERE login = %s",
                        (login,)
                    )

                    row = self.cursor.fetchone()

                    if row:

                        is_deleted = row['is_deleted']

                        if not is_deleted:

                            password_hash = row['password_hash']

                            password = data['password']
                            if verify_password(password, password_hash):
                                client_id = row['id']

                                response = {
                                    'message': 'Successful login.',
                                    'id': client_id
                                }

                            else:
                                response['message'] = 'Incorrect login or password.'

                        else:
                            response['message'] = 'This account is deleted.'

                    else:
                        response['message'] = 'Incorrect login or password.'


                except (mysql.connector.Error, mysql.connector.ProgrammingError,
                        mysql.connector.InterfaceError, mysql.connector.DatabaseError,
                        mysql.connector.OperationalError) as e:

                    response['message'] = f'An error occurred - {e}'

                message_to_service_proxy = {
                    'request': 'login',
                    'request_code': '110',
                    'response_code': '999',
                    'data': response
                }

                self.send_to_service_proxy(message_to_service_proxy)

            elif message_from_service_proxy['request_code'] == '103':
                self.stop_flag = True
                self.cursor.close()
                self.db_connection.close()

            time.sleep(0.001)

