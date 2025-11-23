import random
import string
from faker import Faker

fake = Faker()

# URL Shortener -----------------------------------------------------
def generate_short_url():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

# Fake Data Generator -----------------------------------------------
def get_fake_profile():
    return {
        "name": fake.name(),
        "email": fake.email(),
        "phone": fake.phone_number(),
        "address": fake.address()
    }

# SMS Simulation -----------------------------------------------------
def send_sms(number, message):
    print("\n--- Simulated SMS Sent ---")
    print(f"To: {number}")
    print(f"Message: {message}")
    print("--------------------------\n")
    return True
