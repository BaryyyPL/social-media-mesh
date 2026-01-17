import queue
import threading
import time

import mysql.connector
from mysql.connector import Error

from cryptography_process import symmetric_key_decrypt


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

        self.cursor = self.db_connection.cursor()

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

            if message_from_service_proxy['request_code'] == '115':

                response = {
                    'message': None,
                    'files': []
                }

                try:

                    self.cursor.execute('''
                        SELECT files.filename, files.description, files.create_time,
                               CASE WHEN users.is_deleted = 1 THEN 'Deleted account' ELSE users.login END AS login
                        FROM files
                        JOIN users ON users.id = files.owner_id
                        ORDER BY files.create_time DESC
                    ''')

                    rows = self.cursor.fetchall()

                    if rows:

                        for row in rows:
                            filename = row[0]
                            decrypted_filename = symmetric_key_decrypt(self.database_symmetrical_key, filename)

                            description = row[1]
                            decrypted_description = symmetric_key_decrypt(self.database_symmetrical_key, description)

                            response['files'].append({
                                'filename': decrypted_filename,
                                'description': decrypted_description,
                                'create_time': (row[2].strftime('%Y-%m-%d %H:%M:%S')
                                                if hasattr(row[2], 'utctime') else str(row[2])),
                                'author': row[3]
                            })

                    else:
                        response['message'] = 'No files'

                except Exception as e:
                    response['message'] = f'An error occurred - {e}'

                message_to_service_proxy = {
                    'request': 'available_files',
                    'request_code': '115',
                    'response_code': '999',
                    'data': response
                }

                self.send_to_service_proxy(message_to_service_proxy)

            elif message_from_service_proxy['request_code'] == '103':
                self.stop_flag = True
                self.cursor.close()
                self.db_connection.close()

            time.sleep(0.001)

