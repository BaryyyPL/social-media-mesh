import queue
import threading
import time

import mysql.connector
from mysql.connector import Error

from cryptography_process import symmetric_key_decrypt


class Service:
    def __init__(self, service_proxy_queue_to_service, service_proxy_queue_from_service,
                 database_host, database_user, database_password, database_database, database_port,
                 database_symmetrical_key):

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
            raise SystemExit('Cannot connect to database')

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
            return self.service_proxy_queue_to_service.get(timeout=1.0)
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
                print('Database connected')
                return connection

        except Error as e:
            print(f'Database connection error: {e}')

        return None

    def communication_with_service_proxy(self):

        while not self.stop_flag:

            message_from_service_proxy = self.receive_from_service_proxy()
            if message_from_service_proxy is None:
                continue

            if message_from_service_proxy['request_code'] == '112':

                data = message_from_service_proxy['data']

                number = data['number']

                query = None
                params = None
                good_number_flag = True

                response = {
                    'message': None,
                    'posts': [],
                    'good_number_flag': True
                }

                if number == 'all':
                    query = '''
                        SELECT posts.contents, posts.create_time,
                               CASE WHEN users.is_deleted = 1 THEN 'Deleted account' ELSE users.login END AS login
                        FROM posts
                        JOIN users ON users.id = posts.author_id
                        ORDER BY posts.create_time DESC
                    '''
                elif number.isnumeric():
                    query = '''
                        SELECT posts.contents, posts.create_time,
                               CASE WHEN users.is_deleted = 1 THEN 'Deleted account' ELSE users.login END AS login
                        FROM posts
                        JOIN users ON users.id = posts.author_id
                        ORDER BY posts.create_time DESC
                        LIMIT %s
                    '''
                    params = (int(number),)


                else:
                    response['message'] = 'Invalid number'
                    good_number_flag = False
                    response['good_number_flag'] = False

                try:

                    if good_number_flag:

                        if params:
                            self.cursor.execute(query, params)
                        else:
                            self.cursor.execute(query)

                        rows = self.cursor.fetchall()

                        if rows:

                            for row in rows:
                                contents = row['contents']
                                decrypted_contents = symmetric_key_decrypt(self.database_symmetrical_key, contents).decode()

                                response['posts'].append({
                                    'contents': decrypted_contents,
                                    'create_time': (row['create_time'].strftime('%Y-%m-%d %H:%M:%S')
                                                    if hasattr(row['create_time'], 'utctime')
                                                    else str(row['create_time'])),
                                    'author': row['login']
                                })

                        else:
                            response['message'] = 'No posts'

                except (mysql.connector.Error, mysql.connector.ProgrammingError,
                        mysql.connector.InterfaceError, mysql.connector.DatabaseError,
                        mysql.connector.OperationalError) as e:
                    response['message'] = f'An error occurred - {e}'

                message_to_service_proxy = {
                    'request': 'read_posts',
                    'request_code': '112',
                    'response_code': '999',
                    'data': response
                }

                self.send_to_service_proxy(message_to_service_proxy)

            elif message_from_service_proxy['request_code'] == '103':
                self.stop_flag = True
                self.cursor.close()
                self.db_connection.close()

            time.sleep(0.001)

