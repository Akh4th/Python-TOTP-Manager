import json
import getpass
import os


def get_user_input(prompt, secure=False):
    if secure:
        return getpass.getpass(prompt)
    else:
        return input(prompt)


def create_config_file():
    while True:
        main_password = get_user_input("Enter main password: ", secure=True)
        confirm_password = get_user_input("Confirm main password: ", secure=True)
        if main_password == confirm_password:
            break
        else:
            print("Passwords do not match. Please try again.")
    salt = get_user_input("Enter SALT (default is 'salt_'): ").strip()
    if not salt:
        salt = b'salt_'
    else:
        salt = salt.encode('utf-8')
    totp_file = get_user_input("Enter TOTP file path: ").strip()
    while True:
        if not totp_file:
            print("Please provide a valid TOTP file path.")
        elif not os.path.isfile(totp_file):
            try:
                with open(totp_file, 'w') as f:
                    pass
                print(f"TOTP file '{totp_file}' created.")
                False
            except Exception as e:
                print(f"Error creating TOTP file '{totp_file}': {e}")
        else:
            break
        totp_file = input("Enter TOTP file path: ").strip()
    config = {
        "password": main_password,
        "salt": salt.decode('utf-8'),
        "totp_file": totp_file
    }
    with open('config.json', 'w') as config_file:
        json.dump(config, config_file, indent=4)

    print("Configuration saved to 'config.json'.")


if __name__ == "__main__":
    create_config_file()
