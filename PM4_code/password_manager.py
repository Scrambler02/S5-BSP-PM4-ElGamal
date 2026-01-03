import os
import hashlib
import json
import tkinter as tk

# Return path to file where hased + salted password is stored
def get_password_file():
    home = os.path.expanduser("~")
    folder = os.path.join(home, ".pixelmask")
    os.makedirs(folder, exist_ok=True) # Create folder if doesn't exist
    return os.path.join(folder, "password.json")

def hash_password(password: str, salt: bytes):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000
    )

# Hash + store new password
def set_password(password: str):
    salt = os.urandom(16) # Generate random salt
    hashed = hash_password(password, salt)

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
    new_hash = hash_password(password, salt)

    # Compare hashes
    return new_hash == stored_hash


# Display login window to verify password (or create password on first run)
def run_login_screen():
    stored_pw = load_password_data()
    first_run = stored_pw is None # No password saved yet

    login = tk.Tk()
    login.title("Create Password" if first_run else "Pixel Mask Login")
    login.geometry("300x180+600+300")
    login.resizable(False, False)

    # Prompt text
    label_text = "Create a password:" if first_run else "Enter password:"
    tk.Label(login, text=label_text).pack(pady=10)

    # Password entry
    pw_entry = tk.Entry(login, show="*", width=25)
    pw_entry.pack()
    pw_entry.focus()

    # Confirm password only on first run
    confirm_entry = None
    if first_run:
        tk.Label(login, text="Confirm password:").pack(pady=5)
        confirm_entry = tk.Entry(login, show="*", width=25)
        confirm_entry.pack()

    # Error message label
    error_label = tk.Label(login, text="", fg="red")
    error_label.pack(pady=5)

    result = {"success": False}

    # Handle login or password creation
    def submit(event=None):
        pw = pw_entry.get()

        if not pw:
            error_label.config(text="Password cannot be empty")
            return

        if first_run:
            # Create and store password
            if pw != confirm_entry.get():
                error_label.config(text="Passwords do not match")
                return

            set_password(pw)
            result["success"] = True
            login.destroy()
        else:
            # Verify existing password
            if verify_password(pw):
                result["success"] = True
                login.destroy()
            else:
                error_label.config(text="Incorrect password")

    # Bind Enter key and button
    pw_entry.bind("<Return>", submit)
    if confirm_entry:
        confirm_entry.bind("<Return>", submit)

    tk.Button(
        login,
        text="Create Password" if first_run else "Login",
        command=submit
    ).pack(pady=10)

    login.mainloop()
    return result["success"]