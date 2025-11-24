# ui_setup.py
import tkinter as tk
from PIL import Image, ImageTk
import darkdetect

class PixelMaskUI:
    def __init__(self, root):
        self.root = root
        self.create_widgets()
        self.detect_system_colour()

    def detect_system_colour(self):
        if darkdetect.isDark():
            self.set_dark_mode()
        else:
            self.set_light_mode()

    def create_widgets(self):
        # Column configuration
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=3)
        self.root.rowconfigure(0, weight=1)

        # Left panel
        self.left_panel = tk.Frame(self.root)
        self.left_panel.grid(row=0, column=0, sticky='nsew')
        self.canvas = tk.Canvas(self.left_panel, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        # Avatar
        try:
            avatar_path = "assets/big_avatar.png"
            img = Image.open(avatar_path)
            self.avatar_img = ImageTk.PhotoImage(img)
            self.avatar_label = tk.Label(self.left_panel, image=self.avatar_img, bg="#2E2E2E")
            self.avatar_label.place(x=30, y=30)
            self.avatar_name = tk.Label(self.left_panel, text="Echo", fg="white", bg="#2E2E2E",
                                        font=("SF Mono Regular", 12))
            self.avatar_name.place(x=53, y=150)
        except Exception as e:
            print(f"Could not load avatar image: {e}")

        # Right panel
        self.right_panel = tk.Frame(self.root)
        self.right_panel.grid(row=0, column=1, sticky='nsew')
        self.output = tk.Text(self.right_panel, wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True)
        self.output.config(state=tk.DISABLED)

        self.input = tk.Entry(self.right_panel)
        self.input.pack(fill=tk.X)
        # Bindings will be connected from main app

    # Theme methods
    def set_light_mode(self):
        self.root.config(bg="#EBE7E7")
        self.left_panel.config(bg="#FFFFFF")
        self.canvas.config(bg="#FFFFFF")
        self.output.config(bg="#EBE7E7", fg="#000000")
        self.input.config(bg="#EBE7E7", fg="#000000")

    def set_dark_mode(self):
        self.root.config(bg="#1E1E1E")
        self.left_panel.config(bg="#2E2E2E")
        self.canvas.config(bg="#2E2E2E")
        self.output.config(bg="#1E1E1E", fg="#FFFFFF")
        self.input.config(bg="#1E1E1E", fg="#FFFFFF")

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
        self.root.config(bg='#000000')
        self.output.config(bg='#000000', fg='#66FF66', highlightthickness=3, borderwidth=1)
        self.input.config(bg='#000000', fg='#66FF66', highlightthickness=3, borderwidth=1)
        self.left_panel.config(bg="#1E1E1E")
        self.canvas.config(bg="#1E1E1E")
