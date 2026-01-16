from cryptography_process import base64_decode

from pathlib import Path

DESKTOP_PATH = Path.home() / 'Desktop'


def render_registration_message(response):
    print(response['response']['message'])


def render_login_message(response):
    print(response['response']['message'])

    if not response['response']['id'] == False:
        return response['response']['id']


def render_upload_posts_message(response):
    print(response['response']['message'])


def render_read_posts_message(response):
    posts = response['response']['posts']

    for post in posts:
        author = post['author']
        date = post['create_time']
        contents = post['contents']

        print('=' * 60)
        print(f' Author: {author}')
        print(f' Date : {date}')
        print('-' * 60)
        print(contents)
        print('=' * 60)
        print()


def render_upload_files_message(response):
    print(response['response']['message'])


def render_download_files_message(response):
    file_b64 = response['response']['file']
    filename = response['response']['filename']

    file_bytes = base64_decode(file_b64)

    file_path = DESKTOP_PATH / filename
    with open(file_path, 'wb') as f:
        f.write(file_bytes)

    print(f'File saved to desktop: {file_path}')


def render_available_files_message(response):
    files = response['response']['files']

    for file in files:
        author = file['author']
        date = file['create_time']
        filename = file['filename']
        description = file['description']

        print('=' * 60)
        print(f' Author: {author}')
        print(f' Date : {date}')
        print('-' * 60)
        print(filename)
        print(description)
        print('=' * 60)
        print()


def render_delete_account_message(response):
    print(response['response']['message'])
