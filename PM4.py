# Pixel Mask 4.0 - App launch code
import tkinter as tk
from tkinter import filedialog
from threading import Thread
import subprocess
import queue
import darkdetect
import ui_code.pm_text as pmt
import base64
import os
from PIL import Image, ImageTk

import crypt_code.encryption as enc
from ame_code.char_int_elgamal import decode_msg_to_int
from stego_code import lsb_stego as lsb
from stego_code import dct_stego as dct
from ame_code import elgamal_ame as ame


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
        self.sk_a = None # double key
        self.st = 0 # state
        self.iv = 0 # initialization vector

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
                # Generate ElGamal public/private keys
                self.reset_ame_crypt_flags()
                self.pk, self.sk, self.sk_a = ame.create_keys(ame.p, ame.q, ame.g)
                # Save keys to Desktop folder
                desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                ct_file_path = os.path.join(desktop_path, "ame_keys")
                os.makedirs(ct_file_path, exist_ok=True)
                pub_path = os.path.join(ct_file_path, "public_key.txt")
                priv_path = os.path.join(ct_file_path, "private_key.txt")
                doubl_path = os.path.join(ct_file_path, "double_key.txt")
                with open(pub_path, "w") as f:
                    f.write(str(self.pk))
                with open(priv_path, "w") as f:
                    f.write(str(self.sk))
                with open(doubl_path, "wb") as f:
                    f.write((self.sk_a))
                self.output_text(f'Public, private, and double keys saved to ame_keys folder on your desktop')
            elif cmd.lower() == 'load pk':
                # Load public key from file
                self.reset_crypt_flags()
                key_file = filedialog.askopenfilename(
                    title='Select Public Key file',
                    filetypes=[('Text files', '*.txt'), ('PEM files', '*.pem')]
                )
                if key_file:
                    try:
                        with open(key_file, 'r') as f:
                            self.pk = eval(f.read())
                        self.output_text(f'Public key successfully loaded: \n{self.pk}')
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
                        with open(key_file, 'r') as f:
                            self.sk = int(f.read())
                        self.output_text(f'Private key successfully loaded: \n{self.sk}')
                    except Exception as e:
                        self.output_text(f'ERROR: Could not load private key {str(e)}')
            elif cmd.lower() == 'load ska':
                # Load double key from file
                self.reset_crypt_flags()
                key_file = filedialog.askopenfilename(
                    title='Select Double Key file',
                    filetypes=[('Text files', '*.txt'), ('PEM files', '*.pem')]
                )
                if key_file:
                    try:
                        with open(key_file, 'rb') as f:
                            self.sk_a = f.read()
                        self.output_text(f'Double key successfully loaded: \n{self.sk_a}')
                    except Exception as e:
                        self.output_text(f'ERROR: Could not load double key {str(e)}')

            elif cmd.lower() == 'clear keys':
                # Clear all loaded/generated keys
                self.pk = None
                self.sk = None
                self.sk_a = None
                self.st = None
                self.iv = None
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
                self.m = cmd # Decoy message
                self.output_text('Enter secret message:')
                self.ame_aEncrypt_flag = 'secret'
            elif self.ame_aEncrypt_flag == 'secret':
                m_a = cmd # Secret message
                st_start = self.st
                ct, self.st = ame.encode_msg(self.m, m_a, self.pk, self.sk_a, self.iv, self.st)
                self.output_text(f'CIPHERTEXT: {ct} \nST: {self.st} \nIV: {self.iv}')
                self.ame_aEncrypt_flag = False
                desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                ct_file_path = os.path.join(desktop_path, "ciphertext")
                os.makedirs(ct_file_path, exist_ok=True)
                ct_path = os.path.join(ct_file_path, "ct.txt")
                with open(ct_path, "w") as f:
                    f.write("CIPHERTEXT:\n")
                    f.write(str(ct) + "\n\n")
                    f.write("IV:\n")
                    f.write(str(self.iv) + "\n\n")
                    f.write("ST:\n")
                    f.write(str(st_start) + "\n")

            elif cmd.lower() == 'decrypt':
                self.reset_ame_crypt_flags()
                ct_file = filedialog.askopenfilename(
                    title="Select ciphertext file",
                    filetypes=[("Text files", "*.txt")]
                )
                if not ct_file:
                    self.output_text("No file selected")
                    return
                try:
                    with open(ct_file, "r") as f:
                        data = [line.strip() for line in f.readlines()]
                    # ➤ Extract items from ciphertext file
                    i_ct = data.index("CIPHERTEXT:") + 1
                    i_iv = data.index("IV:") + 1
                    i_st = data.index("ST:") + 1
                    cts = eval(data[i_ct]) # list of (c1, c2)
                    iv  = int(data[i_iv])
                    st  = int(data[i_st])
                    # ➤ Use your own decode function correctly
                    secret_msg = ame.decode_msg(cts, st, sk=self.sk, sk_a=None, IV=iv)
                    self.output_text(f"Decoy message: {secret_msg}")
                except Exception as e:
                    self.output_text(f"ERROR: Decryption failure - {e}")

            elif cmd.lower() == 'ame decrypt':
                self.reset_ame_crypt_flags()
                ct_file = filedialog.askopenfilename(
                    title="Select ciphertext file",
                    filetypes=[("Text files", "*.txt")]
                )
                if not ct_file:
                    self.output_text("No file selected")
                    return

                try:
                    with open(ct_file, "r") as f:
                        data = [line.strip() for line in f.readlines()]
                    # ➤ Extract items from ciphertext file
                    i_ct = data.index("CIPHERTEXT:") + 1
                    i_iv = data.index("IV:") + 1
                    i_st = data.index("ST:") + 1

                    raw = eval(data[i_ct])
                    cts = [(int(c1), int(c2)) for (c1, c2) in raw]
                    iv  = int(data[i_iv])
                    st  = int(data[i_st])
                    # ➤ Use your own decode function correctly
                    secret_msg = ame.decode_msg(cts, st, sk=None, sk_a=self.sk_a, IV=iv)
                    self.output_text(f"Secret message: {secret_msg}")

                except Exception as e:
                    self.output_text(f"ERROR: Anamorphic decryption failure - {e}")
        
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
