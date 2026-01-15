def render_registration_message(response):
    print(response['response']['message'])


def render_login_message(response):
    print(response['response']['message'])

    if not response['response']['id'] == False:
        return response['response']['id']