import logging
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(filename='password_manager.log', level=logging.ERROR)

def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    try:
        file = open("key.key", "rb")
        key = file.read()
        file.close()
        return key
    except FileNotFoundError:
        logging.error("Key file not found.")
        print("Key file not found. Please generate a key first.")
        write_key()
        exit(1)
    except Exception as e:
        logging.exception("Error loading key: %s", str(e))
        print("An error occurred while loading the key.")
        exit(1)

key = load_key()
fer = Fernet(key)

def view():
    try:
        with open('passwords.txt', 'r') as f:
            for line in f.readlines():
                data = line.rstrip()
                user, passw = data.split("|")
                print("User:", user, "| Password:",
                      fer.decrypt(passw.encode()).decode())
    except FileNotFoundError:
        logging.error("Password file not found.")
        print("Password file not found. No passwords to display.")
    except Exception as e:
        logging.exception("Error viewing passwords: %s", str(e))
        print("An error occurred while viewing passwords.")

def add():
    try:
        name = input('Account Name: ')
        pwd = input("Password: ")

        with open('passwords.txt', 'a') as f:
            f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")
        print("Password added successfully.")
    except Exception as e:
        logging.exception("Error adding password: %s", str(e))
        print("An error occurred while adding the password.")

while True:
    try:
        mode = input(
            "Would you like to add a new password or view existing ones (view, add), press q to quit? ").lower()
        if mode == "q":
            break

        if mode == "view":
            view()
        elif mode == "add":
            add()
        else:
            print("Invalid mode.")
            continue
    except KeyboardInterrupt:
        print("\nExiting...")
        break
    except Exception as e:
        logging.exception("Unexpected error: %s", str(e))
        print("An unexpected error occurred. Exiting.")
        break
