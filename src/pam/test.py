# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php

'''
Test function for the python pam module

Run like this: python3 -m pam.test
'''

import sys

from . import PamAuthenticator
from . import PAM_SUCCESS


def main():
    import readline
    import getpass

    def input_with_prefill(prompt, text):
        def hook():
            readline.insert_text(text)
            readline.redisplay()

        readline.set_pre_input_hook(hook)

        if sys.version_info >= (3,):
            result = input(prompt)  # nosec (bandit; python2)
        else:
            result = raw_input(prompt)  # noqa:F821

        readline.set_pre_input_hook()

        return result

    pam = PamAuthenticator()

    username = input_with_prefill('Username: ', getpass.getuser())

    # enter a valid username and an invalid/valid password, to verify both
    # failure and success
    pam.authenticate(username, getpass.getpass(),
                     env={"XDG_SEAT": "seat0"},
                     call_end=False)
    print('Auth result: {} ({})'.format(pam.reason, pam.code))

    env_list = pam.getenvlist()
    for key, value in env_list.items():
        print("Pam Environment List item: {}={}".format(key, value))

    key = "XDG_SEAT"
    value = pam.getenv(key)
    print("Pam Environment item: {}={}".format(key, value))

    key = "asdf"
    value = pam.getenv(key)
    print("Missing Pam Environment item: {}={}".format(key, value))

    if pam.code == PAM_SUCCESS:
        pam.open_session()
        print('Open session: {} ({})'.format(pam.reason, pam.code))
        if pam.code == PAM_SUCCESS:
            pam.close_session()
            print('Close session: {} ({})'.format(pam.reason, pam.code))
        else:
            pam.end()
    else:
        pam.end()


if __name__ == "__main__":
    main()
