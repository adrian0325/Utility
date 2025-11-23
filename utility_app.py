import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from faker import Faker
import requests 

def init_db():
    """Initializes the SQLite database and creates the users table."""
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
    """Hashes a password using SHA256 and a securely generated salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashed, salt

def register_user(username, password):
    """Adds a new user to the database."""
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
    """Checks the provided credentials against the stored hash and salt."""
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
    """Shortens a given URL using the tinyurl.com service."""
    try:
        response = requests.get(f"http://tinyurl.com/api-create.php?url={long_url}")
        return response.text
    except Exception as e:
        return f"Error shortening URL: {e}"

def send_message(recipient_email, message, sender_email, sender_password):
    """Sends an email message as a demo for a messaging utility."""
    if not all([recipient_email, message, sender_email, sender_password]):
        return "Please fill in all message fields."

    try:
        msg = MIMEText(message)
        msg['Subject'] = 'Message from Utility App'
        msg['From'] = sender_email
        msg['To'] = recipient_email

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls() # Secure the connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        return "Message sent successfully"
    except smtplib.AuthenticationError:
        return "Error: Authentication failed. Check your email/password or App Password settings."
    except Exception as e:
        return f"Error sending message: {str(e)}"

def generate_fake_data(data_type):
    """Generates fake data (name, email, address, phone) using the Faker library."""
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
        

        style = ttk.Style()
        style.configure("TButton", padding=6, font=('Arial', 10), background='#4CAF50', foreground='black')
        style.configure("TLabel", font=('Arial', 12))
        
        self.show_login_screen()

    def show_login_screen(self):
        """Displays the Login screen."""
        self.clear_screen()
        
        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack(expand=True)

        tk.Label(frame, text="User Login", font=('Arial', 16, 'bold')).pack(pady=10)
        
        tk.Label(frame, text="Username:").pack(pady=(10, 0))
        self.username_entry = tk.Entry(frame, width=30)
        self.username_entry.pack()
        
        tk.Label(frame, text="Password:").pack(pady=(10, 0))
        self.password_entry = tk.Entry(frame, show="*", width=30)
        self.password_entry.pack()
        
        tk.Button(frame, text="Login", command=self.login, width=20).pack(pady=10)
        tk.Button(frame, text="New User? Register", command=self.show_register_screen, width=20).pack()

    def show_register_screen(self):
        """Displays the Register screen."""
        self.clear_screen()
        
        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack(expand=True)

        tk.Label(frame, text="User Registration", font=('Arial', 16, 'bold')).pack(pady=10)
        
        tk.Label(frame, text="Username:").pack(pady=(10, 0))
        self.reg_username_entry = tk.Entry(frame, width=30)
        self.reg_username_entry.pack()
        
        tk.Label(frame, text="Password:").pack(pady=(10, 0))
        self.reg_password_entry = tk.Entry(frame, show="*", width=30)
        self.reg_password_entry.pack()
        
        tk.Button(frame, text="Register", command=self.register, width=20).pack(pady=10)
        tk.Button(frame, text="Back to Login", command=self.show_login_screen, width=20).pack()

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
        """Displays the main utility menu."""
        self.clear_screen()
        
        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack(expand=True)

        tk.Label(frame, text=f"Welcome, {self.current_user}!", font=('Arial', 16, 'bold')).pack(pady=10)
        tk.Label(frame, text="Choose a Utility:").pack(pady=5)
        
        tk.Button(frame, text="🌐 URL Shortener", command=self.show_url_shortener, width=30).pack(pady=8)
        tk.Button(frame, text="📧 Send Message (Email Demo)", command=self.show_messenger, width=30).pack(pady=8)
        tk.Button(frame, text="👤 Generate Fake Data", command=self.show_fake_data, width=30).pack(pady=8)
        
        tk.Button(frame, text="Logout", command=self.logout, width=30, bg='red', fg='white').pack(pady=20)


    def show_url_shortener(self):
        """Displays the URL Shortener interface."""
        self.clear_screen()
        tk.Label(self.root, text="URL Shortener", font=('Arial', 14, 'bold')).pack(pady=10)
        
        tk.Label(self.root, text="Enter Long URL:").pack()
        self.url_entry = tk.Entry(self.root, width=50)
        self.url_entry.pack(pady=5)
        
        tk.Button(self.root, text="Shorten URL", command=self.shorten, width=20).pack(pady=10)
        
        self.shortened_label = tk.Label(self.root, text="Shortened URL will appear here.", wraplength=450)
        self.shortened_label.pack(pady=10)
        
        tk.Button(self.root, text="← Back to Menu", command=self.show_main_screen, width=20).pack(pady=20)

    def shorten(self):
        long_url = self.url_entry.get().strip()
        if not long_url:
            self.shortened_label.config(text="Please enter a URL to shorten.")
            return
        
        self.shortened_label.config(text="Shortening... Please wait.")
        self.root.update() # Update the GUI immediately
        
        short_url = shorten_url(long_url)
        self.shortened_label.config(text=f"Shortened URL:\n{short_url}", fg='blue')

    def show_messenger(self):
        """Displays the Email Messenger interface."""
        self.clear_screen()
        tk.Label(self.root, text="Send Message (Email Demo)", font=('Arial', 14, 'bold')).pack(pady=10)
        
        frame = tk.Frame(self.root)
        frame.pack(padx=20, pady=10)

        tk.Label(frame, text="Recipient Email:").grid(row=0, column=0, sticky='w', pady=2)
        self.recipient_entry = tk.Entry(frame, width=40)
        self.recipient_entry.grid(row=0, column=1, pady=2)

        tk.Label(frame, text="Your Email:").grid(row=1, column=0, sticky='w', pady=2)
        self.sender_email_entry = tk.Entry(frame, width=40)
        self.sender_email_entry.grid(row=1, column=1, pady=2)
        
        tk.Label(frame, text="Your App Password:").grid(row=2, column=0, sticky='w', pady=2)
        self.sender_pass_entry = tk.Entry(frame, show="*", width=40)
        self.sender_pass_entry.grid(row=2, column=1, pady=2)
        
        tk.Label(self.root, text="Message Content:").pack(pady=(10, 0))
        self.message_entry = tk.Text(self.root, height=5, width=50, padx=5, pady=5)
        self.message_entry.pack()
        
        tk.Button(self.root, text="Send Email", command=self.send_msg, width=20).pack(pady=10)
        
        self.msg_status_label = tk.Label(self.root, text="", wraplength=450, fg='green')
        self.msg_status_label.pack()
        
        tk.Button(self.root, text="← Back to Menu", command=self.show_main_screen, width=20).pack(pady=10)

    def send_msg(self):
        recipient = self.recipient_entry.get().strip()
        message = self.message_entry.get("1.0", tk.END).strip()
        sender_email = self.sender_email_entry.get().strip()
        sender_pass = self.sender_pass_entry.get().strip()
        
        self.msg_status_label.config(text="Sending message... Please wait.", fg='orange')
        self.root.update()
        
        status = send_message(recipient, message, sender_email, sender_pass)
        
        color = 'red' if 'Error' in status else 'green'
        self.msg_status_label.config(text=status, fg=color)

    def show_fake_data(self):
        """Displays the Fake Data Generator interface."""
        self.clear_screen()
        tk.Label(self.root, text="Fake Data Generator", font=('Arial', 14, 'bold')).pack(pady=10)
        
        tk.Label(self.root, text="Select Data Type:").pack()
        
        self.data_type = ttk.Combobox(self.root, values=["name", "email", "address", "phone"], state="readonly", width=25)
        self.data_type.current(0) # Select 'name' as default
        self.data_type.pack(pady=5)
        
        tk.Button(self.root, text="Generate Data", command=self.generate, width=20).pack(pady=10)
        
        self.fake_data_label = tk.Label(self.root, text="Generated result will appear here.", wraplength=450)
        self.fake_data_label.pack(pady=10)
        
        tk.Button(self.root, text="← Back to Menu", command=self.show_main_screen, width=20).pack(pady=20)

    def generate(self):
        data_type = self.data_type.get()
        if not data_type:
            self.fake_data_label.config(text="Please select a data type.")
            return

        fake_data = generate_fake_data(data_type)
        self.fake_data_label.config(text=f"Generated {data_type.upper()}:\n{fake_data}", fg='black')

    def logout(self):
        """Resets state and returns to the login screen."""
        self.logged_in = False
        self.current_user = None
        messagebox.showinfo("Logout", "You have been logged out successfully.")
        self.show_login_screen()

    def clear_screen(self):
        """Destroys all widgets on the root window."""
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    init_db() # Ensure the database is ready
    root = tk.Tk()
    app = UtilityApp(root)
    root.mainloop()