import tkinter as tk
from password_manager import verify_password

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