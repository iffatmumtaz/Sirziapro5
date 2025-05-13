import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Data file and security configurations
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# Initialize session state
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Load user data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save user data
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Generate encryption key from passphrase
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

# Hash password for secure storage
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# Encrypt text
def encrypt_text(text, passkey):
    cipher = Fernet(generate_key(passkey))
    return cipher.encrypt(text.encode()).decode()

# Decrypt text
def decrypt_text(encrypted_text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Load data at the start
stored_data = load_data()

# Navigation menu
st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home section
if choice == "Home":
    st.subheader("Welcome to My 🔐 Data Encryption System Using Streamlit!")
    st.markdown("""
    Develop a Streamlit-based secure data storage and retrieval system where:
    - Users store data with a unique passkey.
    - Users decrypt data by providing the correct passkey.
    - Multiple failed attempts result in a forced reauthorization (login page).
    - The system operates entirely in memory without external databases.
    """)

# User registration
elif choice == "Register":
    st.subheader("✏ Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Both fields are required")

# User login
elif choice == "Login":
    st.subheader("🔑 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏰ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid Credentials. Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🛑 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# Store data section
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔓 Please login first")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt And Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("All fields are required")

# Retrieve data section
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔓 Please login first")
    else:
        st.subheader("🔎 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found!")
        else:
            st.write("Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Enter Encrypted Text to Decrypt")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data")
