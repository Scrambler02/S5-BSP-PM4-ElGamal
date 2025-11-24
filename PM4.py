# Pixel Mask 4.0 Application - User Interface
import tkinter as tk
from tkinter import filedialog
from threading import Thread
import subprocess
import queue
import darkdetect
import pm_text as pmt
import base64
import os
from cryptography.hazmat.primitives import serialization
from PIL import Image, ImageTk


import encryption as enc
from stego_code import lsb_stego as lsb
from stego_code import dct_stego as dct
from ame_code import xor_rsa_ame as ame


class PixelMaskApp4(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Pixel Mask 3.0')
        self.geometry('1200x700')
        self.command_history= []
        self.command_history_index = -1
        self.reset_flag = False
        # Cryptorgaphy operations flags
        self.create_key_flag = False
        self.load_key_flag = False
        self.encrypt_flag = False
        self.decrypt_flag = False
        # Steganography operations flags
        self.lsb_mask_flag = False
        self.lsb_unmask_flag = False
        self.dct_mask_flag = False
        self.dct_unmask_flag = False
        self.convert_to_jpg_flag = False
        
        # AME operations flags
        self.ame_mode_flag = False
        self.ame_keys_prompt = False
        self.ame_aEncrypt_flag = False
        self.ame_decrypt_flag = False
        self.ame_cover_decrypt_flag = False
        # AME keys
        self.pk = None # public key
        self.sk = None # private key
        self.k1 = None # cover key
        self.k2 = None # double key

        self.create_widgets()
        self.detect_system_colour()

        # Attach avatar (from another file)
        # self.avatar = AvatarDisplay(self)
        # self.avatar.place(x=20, y=50)


# ======== GUI SETUP + KEYBOARD SHORTCUTS ======== #


        # Run computer commands in a subprocess shell
        self.cmd_queue = queue.Queue()
        self.shell = subprocess.Popen(
            ['bash'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        # Read subprocess input without blocking the CLI
        Thread(target=self.read_output, daemon=True).start()

    def detect_system_colour(self):
        is_dark_mode = darkdetect.isDark()
        if is_dark_mode:
            self.set_dark_mode()
        else:
            self.set_light_mode()

    # Create main window with two columns
    def create_widgets(self):
        self.columnconfigure(0, weight=1)  # Smaller left panel
        self.columnconfigure(1, weight=3)  # Larger right panel
        self.rowconfigure(0, weight=1)     # Make the row expandable

        # Left Frame -> placeholder for virtual assistant
        self.left_panel = tk.Frame(self)
        self.left_panel.grid(row=0, column=0, sticky='nsew')
        self.canvas = tk.Canvas(self.left_panel, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        try:
            avatar_path = "assets/big_echo.png"
            img = Image.open(avatar_path)
            self.avatar_img = ImageTk.PhotoImage(img)

            # Create label to show avatar
            self.avatar_label = tk.Label(self.left_panel, image=self.avatar_img, bg="#2E2E2E")
            self.avatar_label.place(x=-14, y=70)

            # Optional: display user name below avatar
            self.avatar_name = tk.Label(self.left_panel, text="Echo", fg="white", bg="#2E2E2E", font=("SF Mono", 20))
            self.avatar_name.place(x=162, y=510)
        except Exception as e:
            print(f"Could not load avatar image: {e}")


        # Right Frame -> Command line interface
        self.right_panel = tk.Frame(self)
        self.right_panel.grid(row=0, column=1, sticky='nsew')

        # Text output box -> inside right panel
        self.output = tk.Text(self.right_panel, wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True)
        self.output.config(state=tk.DISABLED)
        self.output_text('Default mode active')

        # Text input box -> inside right panel
        self.input = tk.Entry(self.right_panel)
        self.input.pack(fill=tk.X)
        self.input.bind('<Return>', self.process_command)
        self.input.bind('<Up>', self.cycle_previous_command)
        self.input.bind('<Down>', self.cycle_next_command)

        # Keyboard shortcuts to clear terminal
        self.bind_all('<Command-k>', self.handle_clear_shortcut)
        self.bind_all('<Command-l>', self.handle_clear_shortcut)

    # Navigate backwards through command history
    def cycle_previous_command(self, event):
        if self.command_history:
            if self.command_history_index > 0:
                self.command_history_index -= 1
            elif self.command_history_index == -1:
                self.command_history_index = len(self.command_history) - 1

            if 0 <= self.command_history_index < len(self.command_history):
                previous_command = self.command_history[self.command_history_index]
                self.input.delete(0, tk.END)
                self.input.insert(0, previous_command)
        return 'break'

    # Navigate forward through command history
    def cycle_next_command(self, event):
        if self.command_history:
            if self.command_history_index < len(self.command_history) - 1:
                self.command_history_index += 1
                next_command = self.command_history[self.command_history_index]
                self.input.delete(0, tk.END)
                self.input.insert(0, next_command)
            else:
                self.command_history_index = -1
                self.input.delete(0, tk.END)
        return 'break'
    
    # Clear all text in output box
    def clear_terminal(self):
        self.output.config(state=tk.NORMAL)
        self.output.delete('1.0', tk.END)
        self.output.config(state=tk.DISABLED)

    # Allows for use of keyboard shortcut to clear terminal
    def handle_clear_shortcut(self, event=None):
        self.clear_terminal()


# ======== THEME SETUP ======== #


    def set_light_mode(self):
        self.config(bg="#EBE7E7")
        self.output.config(bg='#EBE7E7', fg='#000000', highlightthickness=3, borderwidth=1)
        self.input.config(bg='#EBE7E7', fg='#000000', highlightthickness=3, borderwidth=1)
        self.left_panel.config(bg='#FFFFFF')
        self.canvas.config(bg='#FFFFFF')

    def set_dark_mode(self):
        self.config(bg='#1E1E1E')
        self.output.config(bg='#1E1E1E', fg='#FFFFFF', highlightthickness=3, borderwidth=1)
        self.input.config(bg='#1E1E1E', fg='#FFFFFF', highlightthickness=3, borderwidth=1) 
        self.left_panel.config(bg="#2E2E2E")
        self.canvas.config(bg='#2E2E2E')

    def set_blue_mode(self):
        self.config(bg='#4169E1')
        self.output.config(bg='#4169E1', fg='#FFFFFF', highlightthickness=3, borderwidth=1)
        self.input.config(bg='#4169E1', fg='#FFFFFF', highlightthickness=3, borderwidth=1)
        self.left_panel.config(bg="#537DFB")
        self.canvas.config(bg='#537DFB')

    def set_red_mode(self):
        self.config(bg='#DC143C')
        self.output.config(bg='#DC143C', fg='#FFFFFF', highlightthickness=3, borderwidth=1)
        self.input.config(bg='#DC143C', fg='#FFFFFF', highlightthickness=3, borderwidth=1) 
        self.left_panel.config(bg="#FF1745")
        self.canvas.config(bg="#FF1745")

    def set_hacker_mode(self):
        self.config(bg='#000000')
        self.output.config(bg='#000000', fg='#66FF66', highlightthickness=3, borderwidth=1)
        self.input.config(bg='#000000', fg='#66FF66', highlightthickness=3, borderwidth=1) 
        self.left_panel.config(bg="#1E1E1E")
        self.canvas.config(bg="#1E1E1E")

        try:
            # Load new image
            img = Image.open('assets/big_ame_echo.png')
            self.avatar_img = ImageTk.PhotoImage(img)
            self.avatar_label.config(image=self.avatar_img)

            # Update avatar name color if needed
            self.avatar_name.config(fg="#66FF66", bg="#1E1E1E")
            self.avatar_name.place(x=161, y=530)
            self.avatar_label.config(image=self.avatar_img, bg="#1E1E1E")

        except Exception as e:
            print(f'Failed to change avatar for hacker mode: {e}')


# ======== FLAG RESETTING FUNCTIONS ======== #


    # reset cryptography-related flags
    def reset_crypt_flags(self):
        self.lsb_mask_flag = False
        self.lsb_unmask_flag = False
        self.create_key_flag = False
        self.load_key_flag = False
        self.convert_to_jpg_flag = False
        self.encrypt_flag = False
        self.decrypt_flag = False
        self.dct_mask_flag = False
        self.dct_unmask_flag = False

    # reset AME cryptography-related flags
    def reset_ame_crypt_flags(self):
        self.ame_keys_prompt = False
        self.ame_aEncrypt_flag = False
        self.ame_decrypt_flag = False
        self.ame_aDecrypt_flag = False

    # reset AME mode flags
    def reset_ame_flags(self):
        self.ame_mode_flag = False
        self.ame_keys_prompt = False
        self.ame_aEncrypt_flag = False
        self.ame_decrypt_flag = False
        self.ame_aDecrypt_flag = False


# ======== TERMINAL OUTPUT FUNCTIONS ======== #


    # Read output from the subprocess
    def read_output(self):
        for line in self.shell.stdout:
            self.cmd_queue.put(line)
            self.update_output()

    # Print new shell output in the output box
    def update_output(self):
        while not self.cmd_queue.empty():
            line = self.cmd_queue.get()
            self.output.config(state=tk.NORMAL)
            self.output.insert(tk.END, line)
            self.output.config(state=tk.DISABLED)
            self.output.see(tk.END)

    # Helper function to format PM output
    def output_text(self, msg: str):
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, f'#PM_ {msg}\n')
        self.output.config(state=tk.DISABLED)
        self.output.see(tk.END)

    # Reset CLI to default mode
    def start_default_mode(self):
        self.reset_ame_flags()
        self.create_widgets()
        self.detect_system_colour()
        self.handle_clear_shortcut()
        self.output_text('Default mode active')
        self.input.focus_set()


# ======== COMMAND PROCESSING ======== #


    # Handle commands entered by user
    def process_command(self, event):
        cmd = self.input.get().strip() # Get the text
        self.input.delete(0, tk.END) # Clear input box
        if cmd:
            self.command_history.append(cmd) # Save to command history
            self.command_history_index = len(self.command_history)
        # Print command to output box
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, f'$ {cmd}\n')
        self.output.config(state=tk.DISABLED)
        self.output.see(tk.END)

        # -- MODE SWITCH COMMANDS -- #
        if cmd.lower() == 'light mode' and self.ame_mode_flag == False:
            self.set_light_mode()
            self.output_text('Switched to light mode')
        elif cmd.lower() == 'dark mode' and self.ame_mode_flag == False:
            self.set_dark_mode()
            self.output_text('Switched to dark mode')
        elif cmd.lower() == 'red mode' and self.ame_mode_flag == False:
            self.set_red_mode()
            self.output_text('Switched to red mode')
        elif cmd.lower() == 'blue mode' and self.ame_mode_flag == False:
            self.set_blue_mode()
            self.output_text('Switched to blue mode')
        # -- HELP COMMANDS -- #
        elif cmd.lower() == 'clear':
            self.clear_terminal()
            self.start_default_mode()
        elif cmd.lower() == 'cancel':
            self.reset_crypt_flags()
            self.output_text('Operation canceled')
        elif cmd.lower() == 'commands' and self.ame_mode_flag == False:
            self.open_cmds_window()
        elif cmd.lower() == 'about':
            self.output_text(pmt.about_info)
        elif cmd.lower() == 'stego' and self.ame_mode_flag == False:
            self.output_text(pmt.stego_text)
        elif cmd.lower() == 'stego help':
            self.output_text(pmt.stego_help)
        elif cmd.lower() == 'ame':
            self.output_text(pmt.ame_text)
        elif cmd.lower() == 'ame help':
            self.output_text(pmt.ame_help)
        elif cmd.lower() == 'mode?':
            if self.ame_mode_flag == True:
                self.output_text('Current mode: AME')
            else:
                self.output_text('Current mode: Default')
        # -- AME MODE -- #
        elif cmd.lower() == 'ame mode':
            self.set_hacker_mode()
            self.clear_terminal()
            self.reset_ame_flags()
            self.ame_mode_flag = True
            self.output_text('Anamorphic encryption mode active')
        elif self.ame_mode_flag:
            if cmd.lower() == 'commands':
                self.open_ame_cmds_window()
            elif cmd.lower() == 'exit':
                self.reset_ame_flags()
                self.start_default_mode()
            elif cmd.lower() == 'cancel':
                self.reset_ame_crypt_flags()
            
            # -- AME CRYPTOGRAPHY COMMANDS -- #
            elif cmd.lower() == 'create keys':
                # Generate RSA public/private keys and save to desktop 
                self.reset_ame_crypt_flags()
                self.pk, self.sk = ame.rsa_keys()
                # Convert keys to PEM format
                public_bytes = self.pk.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                private_bytes = self.sk.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                # Save keys to Desktop folder
                desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                rsa_keys_path = os.path.join(desktop_path, "rsa_keys")
                os.makedirs(rsa_keys_path, exist_ok=True)
                pub_path = os.path.join(rsa_keys_path, "public_key.txt")
                priv_path = os.path.join(rsa_keys_path, "private_key.txt")
                with open(pub_path, "wb") as f:
                    f.write(public_bytes)
                with open(priv_path, "wb") as f:
                    f.write(private_bytes)
                self.output_text(f'Public and private keys saved to rsa_keys folder on your desktop')
            elif cmd.lower() == 'load pk':
                # Load public key from file
                self.reset_crypt_flags()
                key_file = filedialog.askopenfilename(
                    title='Select Public Key file',
                    filetypes=[('Text files', '*.txt'), ('PEM files', '*.pem')]
                )
                if key_file:
                    try:
                        with open(key_file, 'rb') as f:
                            key_data = f.read()
                        self.pk = serialization.load_pem_public_key(key_data)
                        self.output_text(f'Public key successfully loaded')
                    except Exception as e:
                        self.output_text(f'ERROR: Could not load public key {str(e)}')
            elif cmd.lower() == 'load sk':
                # Load private key from file
                self.reset_crypt_flags()
                key_file = filedialog.askopenfilename(
                    title='Select Private Key file',
                    filetypes=[('Text files', '*.txt'), ('PEM files', '*.pem')]
                )
                if key_file:
                    try:
                        with open(key_file, 'rb') as f:
                            key_data = f.read()
                        self.sk = serialization.load_pem_private_key(
                            key_data,
                            password=None
                        )
                        self.output_text(f'Private key successfully loaded')
                    except Exception as e:
                        self.output_text(f'ERROR: Could not load private key {str(e)}')
            elif cmd.lower() == 'clear keys':
                # Clear all loaded/generated keys
                self.pk = None
                self.sk = None
                self.k1 = None
                self.k2 = None
                self.output_text('Keys cleared')

            elif cmd.lower() == 'encrypt' and not self.ame_aEncrypt_flag:
                # Start AME encryption
                if self.pk is None:
                    self.output_text('ERROR: Keys not generated or loaded - Please use "create keys" or load the keys before encrypting')
                    return
                self.reset_ame_crypt_flags()
                self.output_text('Enter decoy message:')
                self.ame_aEncrypt_flag = 'decoy'
            elif self.ame_aEncrypt_flag == 'decoy':
                # Save decoy + prompt for secret message
                self.decoy_msg = cmd
                self.output_text('Enter secret message:')
                self.ame_aEncrypt_flag = 'secret'
            elif self.ame_aEncrypt_flag == 'secret':
                # Save messages, encrypt, wrap keys + save to desktop
                secret_msg = cmd
                ct_b64, self.k1, self.k2 = ame.aEncrypt(self.decoy_msg, secret_msg)
                wrapped_k1 = ame.wrap_key(self.pk, self.k1)
                self.k1 = base64.b64encode(wrapped_k1).decode('utf-8')
                wrapped_k2 = ame.wrap_key(self.pk, self.k2)
                self.k2 = base64.b64encode(wrapped_k2).decode('utf-8')
                desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                ame_keys_path = os.path.join(desktop_path, "ame_keys")
                os.makedirs(ame_keys_path, exist_ok=True)
                k1_path = os.path.join(ame_keys_path, "key.txt")
                k2_path = os.path.join(ame_keys_path, "double_key.txt")
                with open(k1_path, "w") as f:
                    f.write(self.k1)
                with open(k2_path, "w") as f:
                    f.write(self.k2)
                self.output_text(f'Ciphertext: {ct_b64.decode()}')
                self.output_text(f'Cover and double keys saved to ame_keys folder on your desktop')
                self.ame_aEncrypt_flag = False

            elif cmd.lower() == 'load k':
                # Load k1 from file
                self.reset_ame_crypt_flags()
                key_file = filedialog.askopenfilename(
                    title='Select k file',
                    filetypes=[('Text files', '*.txt')]
                )
                if not key_file:
                    self.output_text('No file selected')
                else:
                    try:
                        with open(key_file, 'r') as f:
                            self.k1 = f.read().strip()
                        self.output_text('k file loaded successfully')
                    except FileNotFoundError:
                        self.output_text('ERROR: k file not found')
            elif cmd.lower() == 'load dk':
                # Load k2 from file -> double key
                self.reset_ame_crypt_flags()
                key_file = filedialog.askopenfilename(
                    title='Select dk file',
                    filetypes=[('Text files', '*.txt')]
                )
                if not key_file:
                    self.output_text('No file selected')
                else:
                    try:
                        with open(key_file, 'r') as f:
                            self.k2 = f.read().strip()
                        self.output_text('dk file loaded successfully')
                    except FileNotFoundError:
                        self.output_text('ERROR: dks file not found')

            elif cmd.lower() == 'decrypt':
                # Start decryption -> retrieve cover message
                self.reset_ame_crypt_flags()
                self.output_text('Enter ciphertext:')
                self.ame_cover_decrypt_flag = 'ct'
            elif self.ame_cover_decrypt_flag == 'ct':
                ct_b64 = cmd
                # Check if keys are loaded (k1 + private key)
                if not self.k1:
                    self.output_text("ERROR: k not loaded")
                    self.ame_cover_decrypt_flag = False
                    return
                if self.sk is None:
                    self.output_text("ERROR: Private key not loaded")
                    self.ame_cover_decrypt_flag = False
                    return
                # Perform decryption
                wrapped_k1_bytes = base64.b64decode(self.k1)
                unwrapped_k1 = ame.unwrap_key(self.sk, wrapped_k1_bytes)
                cover_msg = ame.aDecrypt(ct_b64, unwrapped_k1)
                self.output_text(f'Cover message: {cover_msg}')
                self.ame_cover_decrypt_flag = False

            elif cmd.lower() == 'ame decrypt':
                # Start AME decryption -> retrieve secret message
                self.reset_ame_crypt_flags()
                self.output_text('Enter ciphertext:')
                self.ame_aDecrypt_flag = 'ct'
            elif self.ame_aDecrypt_flag == 'ct':
                ct_b64 = cmd
                # Check if keys are loaded (k2 + private key)
                if not self.k2:
                    self.output_text("ERROR: dk not loaded")
                    self.ame_aDecrypt_flag = False
                    return
                if self.sk is None:
                    self.output_text("ERROR: Private key not loaded")
                    self.ame_aDecrypt_flag = False
                    return
                # Perform anamorphic decryption
                wrapped_k2_bytes = base64.b64decode(self.k2)
                unwrapped_k2 = ame.unwrap_key(self.sk, wrapped_k2_bytes)
                secret_msg = ame.aDecrypt(ct_b64, unwrapped_k2)
                self.output_text(f'Secret message: {secret_msg}')
                self.ame_aDecrypt_flag = False
        
        # -- DEFAULT CRYPTOGRAPHY + STEGANOGRAPHY COMMANDS -- #
        elif cmd.lower() == '2jpg':
            # Convert images in PNG format to JPG
            self.png_img_path = filedialog.askopenfilename(
                title='Select PNG Image',
                filetypes=[('Image files', '*png')]
            )
            if self.png_img_path:
                try:
                    if not self.png_img_path.lower().endswith('.png'):
                        self.output_text(f'Error: {self.png_img_path} is not a PNG file')
                        self.convert_to_jpg_flag = False
                    else:
                        lsb.convert_png(self.png_img_path)
                        self.output_text(f"Successfully converted {self.png_img_path} and saved to 'JPG_img' on your Desktop")
                except Exception as e:
                    self.output_text(f'ERROR: Failed to convert PNG - {str(e)}')
                self.convert_to_jpg_flag = False

        elif cmd.lower() == 'create key':
            # Generate AES key from secret value + store in folder
            self.output_text('Enter the secret value to generate the key:')
            self.reset_crypt_flags()
            self.create_key_flag = 'secret_value'
        elif self.create_key_flag == 'secret_value':
            self.secret_value = cmd.encode('utf-8')
            self.output_text('Enter the folder name where you want to store the key:')
            self.create_key_flag = 'folder_name'
        elif self.create_key_flag == 'folder_name':
            folder_name = cmd 
            enc.create_key(self.secret_value, folder_name)
            self.output_text(f'Key successfully created and saved to {folder_name}')
            self.create_key_flag = False 
        elif cmd.lower() == 'load key':
            # Load key from file
            self.reset_crypt_flags()
            self.key = filedialog.askopenfilename(
                title='Select Key file',
                filetypes=[('Text files', '*txt')]
            )
            try:
                enc.load_key(self.key)
                self.output_text(f'Key successfully loaded')
            except FileNotFoundError:
                self.output_text(f'ERROR: Key file not found')

        elif cmd.lower() == 'encrypt':
            # Start default encryption -> using loaded key
            self.output_text('Enter the message to encrypt:')
            self.reset_crypt_flags()
            self.encrypt_flag = True 
        elif self.encrypt_flag:
            try: 
                encrypted_message = enc.encrypt(cmd) # Encrypt message
                encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')
                self.output_text(f'{encrypted_message_base64}') # Show encrypted Base64 ciphertext
                self.encrypt_flag = False
            except FileNotFoundError:
                self.output_text(f'ERROR: No key loaded - Please load the key first')
                self.encrypt_flag = False

        elif cmd.lower() == 'decrypt':
            # Start decryption -> using loaded key
            self.output_text('Enter the encrypted message to decrypt:')
            self.reset_crypt_flags()
            self.decrypt_flag = True
        elif self.decrypt_flag:
            try:
                decrypted_message = enc.decrypt(cmd) # Decrypt message
                self.output_text(f'{decrypted_message}')
                self.decrypt_flag = False
            except FileNotFoundError:
                self.output_text(f'ERROR: No key loaded - Please load the key first')
                self.decrypt_flag = False

        elif cmd.lower() == 'lsb mask':
            # Embed message into image using LSB
            self.cover_img_path = filedialog.askopenfilename(
                title='Select Cover Image',
                filetypes=[('Image files', '*jpg')]
            )
            if self.cover_img_path:
                self.output_text('Enter the message to embed:')
                self.lsb_mask_flag = True
            else:
                self.output_text('No image selected - Operation canceled')
                self.lsb_mask_flag = False
            self.reset_crypt_flags()
            self.lsb_mask_flag = True
        elif self.lsb_mask_flag:
            message = cmd
            response = lsb.mask(self.cover_img_path, message)
            self.output_text(response)
            self.lsb_mask_flag = False
        elif cmd.lower() == 'lsb unmask':
            # Extract message from stego image 
            self.stego_img_path = filedialog.askopenfilename(
                title='Select Stego Image',
                filetypes=[('Image files', '*png')]
            )
            if self.stego_img_path:
                try:
                    response = lsb.unmask(self.stego_img_path)
                    self.output_text(response)
                except Exception as e:
                    self.output_text(f'ERROR: Failed to unmask image - {str(e)}')
                self.lsb_unmask_flag = False
            else:
                self.output_text('No image selected - Operation canceled')
            self.reset_crypt_flags()

        elif cmd.lower() == 'dct mask':
            # Embed message into image using DCT
            self.cover_img_path = filedialog.askopenfilename(
                title='Select Cover Image',
                filetypes=[('Image files', '*.jpg *.png')]
            )
            if self.cover_img_path:
                self.output_text('Enter the message to embed:')
                self.dct_mask_flag = True
            else:
                self.output_text('No image selected - Operation canceled')
                self.dct_mask_flag = False
            self.reset_crypt_flags()
            self.dct_mask_flag = True
        elif self.dct_mask_flag:
            message = cmd
            response = dct.mask(self.cover_img_path, message if isinstance(message, str) else message.decode('utf-8'))
            self.output_text(response)
            self.dct_mask_flag = False
        elif cmd.lower() == 'dct unmask':
            # Extract message from NumPy file 
            self.numpy_file_path = filedialog.askopenfilename(
                title='Select DCT NumPy File',
                filetypes=[('NumPy files', '*.npy')]
            )
            if self.numpy_file_path:
                try:
                    response = dct.unmask(self.numpy_file_path)
                    self.output_text(response)
                except Exception as e:
                    self.output_text(f'ERROR: Failed to unmask file - {str(e)}')
                self.dct_unmask_flag = False
            else:
                self.output_text('No file selected - Operation canceled')
            self.reset_crypt_flags()

        # Otherwise pass command to subprocess shell
        self.shell.stdin.write(cmd + '\n')
        self.shell.stdin.flush()

    def open_cmds_window(self):
        # Open small separate window -> showing available commands
        new_win = tk.Toplevel(self)
        new_win.title('Command help')
        new_win.geometry('400x320')
        text_widget = tk.Text(new_win, wrap=tk.WORD)
        # Insert command text
        text_widget.insert(tk.END, pmt.cmd_txt) 
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True)

    def open_ame_cmds_window(self):
        # Open small separate window -> showing available AME mode commands
        new_win = tk.Toplevel(self)
        new_win.title('Ame command help')
        new_win.geometry('400x320')
        new_win.config(bg='#000000')
        text_widget = tk.Text(new_win, wrap=tk.WORD)
        # Insert AME command text
        text_widget.insert(tk.END, pmt.ame_cmd_txt)
        text_widget.config(
            state=tk.DISABLED,
            bg='#000000',
            fg='#66FF66',
            highlightthickness=3, 
            borderwidth=1)
        text_widget.pack(fill=tk.BOTH, expand=True)

if __name__ == '__main__':
    app = PixelMaskApp4()
    app.mainloop()
