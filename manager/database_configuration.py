from cryptography_process import generate_symmetrical_key, base64_encode

class Database:
    host = '127.0.0.1'
    user = 'root'
    password = ''
    database = 'service_mesh_app_db'
    port = 3306
    database_symmetrical_key = generate_symmetrical_key()

    @classmethod
    def to_dict(cls):
        database_config = {
            'host': cls.host,
            'user': cls.user,
            'password': cls.password,
            'database': cls.database,
            'port': cls.port,
            'database_symmetrical_key': base64_encode(cls.database_symmetrical_key)
        }
        return database_config