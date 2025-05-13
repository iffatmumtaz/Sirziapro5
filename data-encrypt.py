import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


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

# Data handling functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.encrypt(text.encode()).decode()
    except Exception as e:
        st.error(f"Encryption failed: {str(e)}")
        return None

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# Load stored data
stored_data = load_data()

# Navigation
st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "Home":
    st.subheader("Welcome to the 🔐 Data Encryption System Using Streamlit!")
    st.markdown("""
    This is a Streamlit-based secure data storage and retrieval system where:
    - Users can store data with a unique passkey.
    - Users can decrypt data by providing the correct passkey.
    - Multiple failed login attempts result in a temporary lockout.
    - The system operates with file-based storage (no external databases).
    """)

# Register Page
elif choice == "Register":
    st.subheader("✏ Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists!")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("⚠️ Both username and password are required.")

# Login Page
elif choice == "Login":
    st.subheader("🔑 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏰ Too many failed attempts. Please wait {remaining} seconds.")
    else:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.session_state.lockout_time = 0
                st.success(f"✅ Welcome, {username}!")
            else:
                st.session_state.failed_attempts += 1
                remaining_attempts = 3 - st.session_state.failed_attempts
                if remaining_attempts > 0:
                    st.error(f"❌ Invalid credentials. {remaining_attempts} attempts left.")
                else:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("🛑 Too many failed attempts. Locked out for 60 seconds.")
                    st.session_state.failed_attempts = 0

# Store Data Page
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔓 Please login first!")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                if encrypted:
                    stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                    save_data(stored_data)
                    st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("⚠️ Both data and passkey are required.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔓 Please login first!")
    else:
        st.subheader("🔎 Retrieve Decrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found!")
        else:
            st.write("Your Encrypted Data Entries:")
            selected_index = st.selectbox("Select an entry to decrypt", range(len(user_data)), format_func=lambda i: f"Entry {i+1}")
            selected_data = user_data[selected_index]
            st.code(selected_data, language="text")

            passkey = st.text_input("Enter Passkey to Decrypt", type="password")
            if st.button("Decrypt"):
                if passkey:
                    result = decrypt_text(selected_data, passkey)
                    if result:
                        st.success(f"✅ Decrypted Data: {result}")
                    else:
                        st.error("❌ Incorrect passkey or corrupted data.")
                else:
                    st.error("⚠️ Passkey is required.")
