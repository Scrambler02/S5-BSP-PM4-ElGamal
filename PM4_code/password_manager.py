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


# Display login window and verify user password
def run_login_screen():
    login = tk.Tk()
    login.title("Pixel Mask Login")
    login.geometry("300x150+600+300")
    login.resizable(False, False)

    # Password prompt
    tk.Label(login, text="Enter password:").pack(pady=10)
    pw_entry = tk.Entry(login, show="*", width=25)
    pw_entry.pack()
    pw_entry.focus()
    # Style password entry
    pw_entry.config(bg='#1E1E1E', fg='#FFFFFF', highlightthickness=3, borderwidth=1) 

    # Store login result
    result = {"success": False}

    # Attempt login when button pressed or Enter key used
    def try_login(event=None):
        pw = pw_entry.get()
        if verify_password(pw):
            result["success"] = True
            login.destroy() # Close login window on success
        else:
            error_label.config(text="Incorrect password", fg="red")

    # Bind Enter key and Login button
    pw_entry.bind("<Return>", try_login)
    tk.Button(login, text="Login", command=try_login).pack(pady=10)
    
    # Error message label
    error_label = tk.Label(login, text="", fg="red")
    error_label.pack()

    login.mainloop()
    return result["success"]