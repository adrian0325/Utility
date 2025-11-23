import tkinter as tk
from tkinter import messagebox
from login import verify_login
from utilities import generate_short_url, get_fake_profile, send_sms

# ------------------ LOGIN WINDOW ---------------------------------
def login_window():
    win = tk.Tk()
    win.title("Login System")
    win.geometry("300x200")

    tk.Label(win, text="Username").pack()
    username_entry = tk.Entry(win)
    username_entry.pack()

    tk.Label(win, text="Password").pack()
    password_entry = tk.Entry(win, show="*")
    password_entry.pack()

    def try_login():
        user = username_entry.get()
        pw = password_entry.get()

        if verify_login(user, pw):
            messagebox.showinfo("Success", "Login Successful!")
            win.destroy()
            utilities_menu()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    tk.Button(win, text="Login", command=try_login).pack(pady=10)
    win.mainloop()

# ------------------ UTILITIES MENU ---------------------------------
def utilities_menu():
    menu = tk.Tk()
    menu.title("Utilities Menu")
    menu.geometry("300x250")

    tk.Button(menu, text="URL Shortener", width=20, command=url_shortener_gui).pack(pady=10)
    tk.Button(menu, text="SMS Messaging", width=20, command=sms_gui).pack(pady=10)
    tk.Button(menu, text="Fake Data Generator", width=20, command=fake_data_gui).pack(pady=10)

    menu.mainloop()

# ----------- URL SHORTENER GUI ------------------------------------
def url_shortener_gui():
    win = tk.Toplevel()
    win.title("URL Shortener")
    win.geometry("350x200")

    tk.Label(win, text="Enter URL:").pack()
    url_entry = tk.Entry(win, width=40)
    url_entry.pack()

    output = tk.Label(win, text="")
    output.pack(pady=10)

    def shorten():
        short = "https://short.ly/" + generate_short_url()
        output.config(text=f"Short URL: {short}")

    tk.Button(win, text="Shorten URL", command=shorten).pack(pady=10)

# ----------- SMS GUI ----------------------------------------------
def sms_gui():
    win = tk.Toplevel()
    win.title("SMS Messaging")
    win.geometry("350x250")

    tk.Label(win, text="Phone Number:").pack()
    phone_entry = tk.Entry(win)
    phone_entry.pack()

    tk.Label(win, text="Message:").pack()
    msg_entry = tk.Entry(win, width=40)
    msg_entry.pack()

    def send():
        num = phone_entry.get()
        msg = msg_entry.get()
        send_sms(num, msg)
        messagebox.showinfo("Success", "SMS Sent (simulated)")

    tk.Button(win, text="Send SMS", command=send).pack(pady=20)

# ----------- FAKE DATA GUI ----------------------------------------
def fake_data_gui():
    win = tk.Toplevel()
    win.title("Fake Data Generator")
    win.geometry("350x300")

    output = tk.Text(win, height=10, width=40)
    output.pack()

    def generate():
        profile = get_fake_profile()
        output.delete(1.0, tk.END)
        for key, value in profile.items():
            output.insert(tk.END, f"{key.upper()}: {value}\n")

    tk.Button(win, text="Generate Fake Profile", command=generate).pack(pady=10)

# Run program
if __name__ == "__main__":
    login_window()
