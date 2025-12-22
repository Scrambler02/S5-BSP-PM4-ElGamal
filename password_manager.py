import os
import hashlib
import json

# Return path to file where hased + salted password is stored
def get_password_file():
    home = os.path.expanduser("~")
    folder = os.path.join(home, ".pixelmask")
    os.makedirs(folder, exist_ok=True) # Create folder if doesn't exist
    return os.path.join(folder, "password.json")

# Hash + store new password
def set_password(password: str):
    salt = os.urandom(16) # Generate random salt
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt, 
        200000 # Number of hash iterations
    )

    # Store salt and hash as hex strings
    data = {
        "salt": salt.hex(),
        "hash": hashed.hex()
    }

    with open(get_password_file(), "w") as f:
        json.dump(data, f)


# Load stored password hash + salt
def load_password_data():
    path = get_password_file()
    if not os.path.exists(path):
        return None # No password stored

    with open(path, "r") as f:
        data = json.load(f)

    # Convert hex strings back to bytes
    return {
        "salt": bytes.fromhex(data["salt"]),
        "hash": bytes.fromhex(data["hash"])
    }


# Check if entered password matches stored password
def verify_password(password: str):
    stored = load_password_data()
    if stored is None:
        return False # No password set
    
    salt = stored["salt"]
    stored_hash = stored["hash"]

    # Hash input password using stored salt
    new_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000
    )

    # Compare hashes
    return new_hash == stored_hash