import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import * 
from PIL import Image, ImageTk

import sqlite3
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from faker import Faker
import requests 

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                salt TEXT
              )''')
    conn.commit()
    conn.close()

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashed, salt

def register_user(username, password):
    hashed, salt = hash_password(password)
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, hashed, salt))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_login(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        stored_hash, salt = result
        hashed, _ = hash_password(password, salt)
        return hashed == stored_hash
    return False

def shorten_url(long_url):
    try:
        response = requests.get(f"http://tinyurl.com/api-create.php?url={long_url}")
        return response.text
    except Exception as e:
        return f"Error shortening URL: {e}"

def send_message(recipient_email, message, sender_email, sender_password):
    if not all([recipient_email, message, sender_email, sender_password]):
        return "Please fill in all message fields."

    try:
        msg = MIMEText(message)
        msg['Subject'] = 'Message from Utility App'
        msg['From'] = sender_email
        msg['To'] = recipient_email

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        return "Message sent successfully"
    except smtplib.SMTPAuthenticationError:
        return "Error: Authentication failed. Check your email/password or App Password settings."
    except Exception as e:
        return f"Error sending message: {str(e)}"

def generate_fake_data(data_type):
    fake = Faker()
    if data_type == "name":
        return fake.name()
    elif data_type == "email":
        return fake.email()
    elif data_type == "address":
        return fake.address()
    elif data_type == "phone":
        return fake.phone_number()
    else:
        return "Invalid type selected"

class UtilityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Multi-Utility App")
        self.root.geometry("500x550") 
        self.logged_in = False
        self.current_user = None

        self.bg_image = Image.open("123.jpg")
        self.bg_photo = ImageTk.PhotoImage(self.bg_image)
        self.bg_label = tk.Label(self.root, image=self.bg_photo)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.show_login_screen()

    def show_login_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)
        ttk.Label(frame, text="Utility App\n   LOGIN", font=('Arial', 18, 'bold')).pack(pady=10)
        ttk.Label(frame, text="Username:").pack(pady=(10, 0))
        self.username_entry = ttk.Entry(frame, width=30)
        self.username_entry.pack()
        ttk.Label(frame, text="Password:").pack(pady=(10, 0))
        self.password_entry = ttk.Entry(frame, show="*", width=30)
        self.password_entry.pack()
        ttk.Button(frame, text="Login", command=self.login, width=20, bootstyle="success").pack(pady=10)
        ttk.Button(frame, text="New User? Register", command=self.show_register_screen, width=20, bootstyle="info-link").pack()

    def show_register_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)
        ttk.Label(frame, text="User Registration", font=('Arial', 16, 'bold')).pack(pady=10)
        ttk.Label(frame, text="Username:").pack(pady=(10, 0))
        self.reg_username_entry = ttk.Entry(frame, width=30)
        self.reg_username_entry.pack()
        ttk.Label(frame, text="Password:").pack(pady=(10, 0))
        self.reg_password_entry = ttk.Entry(frame, show="*", width=30)
        self.reg_password_entry.pack()
        ttk.Button(frame, text="Register", command=self.register, width=20, bootstyle="primary").pack(pady=10)
        ttk.Button(frame, text="Back to Login", command=self.show_login_screen, width=20, bootstyle="link").pack()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showwarning("Input Error", "Username and Password cannot be empty.")
            return
        if verify_login(username, password):
            self.logged_in = True
            self.current_user = username
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Invalid username or password.")

    def register(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        if not username or not password:
            messagebox.showwarning("Input Error", "Username and Password cannot be empty.")
            return
        if register_user(username, password):
            messagebox.showinfo("Success", f"User '{username}' registered successfully!")
            self.show_login_screen()
        else:
            messagebox.showerror("Error", "Username already exists. Please choose a different one.")

    def show_main_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)
        ttk.Label(frame, text=f"Welcome, {self.current_user}!", font=('Arial', 16, 'bold')).pack(pady=10)
        ttk.Label(frame, text="Choose a Utility:").pack(pady=5)
        ttk.Button(frame, text="🌐 URL Shortener", command=self.show_url_shortener, width=30, bootstyle="primary").pack(pady=8)
        ttk.Button(frame, text="📧 Send Message (Email Demo)", command=self.show_messenger, width=30, bootstyle="info").pack(pady=8)
        ttk.Button(frame, text="👤 Generate Fake Data", command=self.show_fake_data, width=30, bootstyle="secondary").pack(pady=8)
        ttk.Button(frame, text="Logout", command=self.logout, width=30, bootstyle="danger").pack(pady=20)

    def show_url_shortener(self):
        self.clear_screen()
        ttk.Label(self.root, text="URL Shortener", font=('Arial', 14, 'bold')).pack(pady=10)
        ttk.Label(self.root, text="Enter Long URL:").pack()
        self.url_entry = ttk.Entry(self.root, width=50)
        self.url_entry.pack(pady=5)
        ttk.Button(self.root, text="Shorten URL", command=self.shorten, width=20, bootstyle="success").pack(pady=10)
        self.shortened_label = ttk.Label(self.root, text="Shortened URL will appear here.", wraplength=450)
        self.shortened_label.pack(pady=10)
        ttk.Button(self.root, text="← Back to Menu", command=self.show_main_screen, width=20, bootstyle="link").pack(pady=20)

    def shorten(self):
        long_url = self.url_entry.get().strip()
        if not long_url:
            self.shortened_label.config(text="Please enter a URL to shorten.")
            return
        self.shortened_label.config(text="Shortening... Please wait.", bootstyle="warning")
        self.root.update()
        short_url = shorten_url(long_url)
        self.shortened_label.config(text=f"Shortened URL:\n{short_url}", bootstyle="primary")

    def show_messenger(self):
        self.clear_screen()
        ttk.Label(self.root, text="Send Message (Email Demo)", font=('Arial', 14, 'bold')).pack(pady=10)
        frame = ttk.Frame(self.root)
        frame.pack(padx=20, pady=10)
        ttk.Label(frame, text="Recipient Email:").grid(row=0, column=0, sticky='w', pady=2)
        self.recipient_entry = ttk.Entry(frame, width=40)
        self.recipient_entry.grid(row=0, column=1, pady=2)
        ttk.Label(frame, text="Your Email:").grid(row=1, column=0, sticky='w', pady=2)
        self.sender_email_entry = ttk.Entry(frame, width=40)
        self.sender_email_entry.grid(row=1, column=1, pady=2)
        ttk.Label(frame, text="Your App Password:").grid(row=2, column=0, sticky='w', pady=2)
        self.sender_pass_entry = ttk.Entry(frame, show="*", width=40)
        self.sender_pass_entry.grid(row=2, column=1, pady=2)
        ttk.Label(self.root, text="Message Content:").pack(pady=(10, 0))
        self.message_entry = tk.Text(self.root, height=5, width=50, padx=5, pady=5)
        self.message_entry.pack()
        ttk.Button(self.root, text="Send Email", command=self.send_msg, width=20, bootstyle="info").pack(pady=10)
        self.msg_status_label = ttk.Label(self.root, text="", wraplength=450, bootstyle="success")
        self.msg_status_label.pack()
        ttk.Button(self.root, text="← Back to Menu", command=self.show_main_screen, width=20, bootstyle="link").pack(pady=10)

    def send_msg(self):
        recipient = self.recipient_entry.get().strip()
        message = self.message_entry.get("1.0", tk.END).strip()
        sender_email = self.sender_email_entry.get().strip()
        sender_pass = self.sender_pass_entry.get().strip()
        self.msg_status_label.config(text="Sending message... Please wait.", bootstyle="warning")
        self.root.update()
        status = send_message(recipient, message, sender_email, sender_pass)
        style = "danger" if 'Error' in status else "success"
        self.msg_status_label.config(text=status, bootstyle=style)

    def show_fake_data(self):
        self.clear_screen()
        ttk.Label(self.root, text="Fake Data Generator", font=('Arial', 14, 'bold')).pack(pady=10)
        ttk.Label(self.root, text="Select Data Type:").pack()
        self.data_type = ttk.Combobox(self.root, values=["name", "email", "address", "phone"], state="readonly", width=25)
        self.data_type.current(0)
        self.data_type.pack(pady=5)
        ttk.Button(self.root, text="Generate Data", command=self.generate, width=20, bootstyle="secondary").pack(pady=10)
        self.fake_data_label = ttk.Label(self.root, text="Generated result will appear here.", wraplength=450)
        self.fake_data_label.pack(pady=10)
        ttk.Button(self.root, text="← Back to Menu", command=self.show_main_screen, width=20, bootstyle="link").pack(pady=20)

    def generate(self):
        data_type = self.data_type.get()
        if not data_type:
            self.fake_data_label.config(text="Please select a data type.")
            return
        fake_data = generate_fake_data(data_type)
        self.fake_data_label.config(text=f"Generated {data_type.upper()}:\n{fake_data}", bootstyle="inverse-light")

    def logout(self):
        self.logged_in = False
        self.current_user = None
        messagebox.showinfo("Logout", "You have been logged out successfully.")
        self.show_login_screen()

    def clear_screen(self):
        self.bg_label.lift()
        for widget in self.root.winfo_children():
            if widget != self.bg_label:
                widget.destroy()

if __name__ == "__main__":
    init_db()
    root = ttk.Window(themename="superhero") 
    app = UtilityApp(root)
    root.mainloop()
