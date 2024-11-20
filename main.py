import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, ttk
import hashlib
import json
import os
from cryptography.fernet import Fernet
from PIL import Image, ImageTk

# Path to the file that stores users data
users_file = "users.json"
  # Example: Supported image extensions
SUPPORTED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.bmp', '.gif']

# Function to hash password for user authentication
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Load users from the file (if it exists)
def load_users():
    if os.path.exists(users_file):
        with open(users_file, "r") as file:
            return json.load(file)
    return {}

# Save users to the file
def save_users(users):
    with open(users_file, "w") as file:
        json.dump(users, file)

# Mock user database
users = load_users()

# Function to validate user login
def login(username, password):
    hashed_password = hash_password(password)
    if username in users:
        return users[username] == hashed_password
    return False

# Function to register a new user
def register(username, password):
    if username in users:
        return False  # User already exists
    users[username] = hash_password(password)
    save_users(users)  # Save updated user data to the file
    return True

# Function to show the main application window
def show_main_window():
    # Generate an encryption key
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

    # Create directories if they do not exist
    if not os.path.exists("encrypted_photos"):
        os.makedirs("encrypted_photos")
    if not os.path.exists("decrypted_photos"):
        os.makedirs("decrypted_photos")

    # Create the main application window
    main_window = tk.Toplevel(root)
    main_window.title("Photo Encryption")
    main_window.geometry("400x350+500+200")
    main_window.configure(bg="#f5f5f5")

    # Ensure the program exits when this window is closed
    main_window.protocol("WM_DELETE_WINDOW", root.destroy)

    # Title
    title_label = tk.Label(main_window, text="Photo Encryption System", font=("Arial", 16, "bold"), bg="#f5f5f5", fg="#0078D4")
    title_label.pack(pady=15)

    # Function to encrypt the photo
    def encrypt_photo():
        file_path = filedialog.askopenfilename(title="Select a photo to encrypt", filetypes=[("Image Files", "*.jpg *.jpeg *.png")])
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    photo_data = file.read()
                    encrypted_data = cipher_suite.encrypt(photo_data)

                enc_filename = "enc_" + os.path.basename(file_path)
                enc_path = os.path.join("encrypted_photos", enc_filename)
                with open(enc_path, "wb") as enc_file:
                    enc_file.write(encrypted_data)

                messagebox.showinfo("Success", f"Photo encrypted and saved as: {enc_filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    # Function to decrypt the photo
    def decrypt_photo():
        enc_filename = simpledialog.askstring("Decrypt", "Enter the encrypted filename ")
        if enc_filename:
            file_path = os.path.join("encrypted_photos", enc_filename)
            if os.path.exists(file_path):
                try:
                    with open(file_path, "rb") as file:
                        encrypted_data = file.read()
                        decrypted_data = cipher_suite.decrypt(encrypted_data)

                    dec_filename = "dec_" + enc_filename.replace("enc_", "")
                    dec_path = os.path.join("decrypted_photos", dec_filename)
                    with open(dec_path, "wb") as dec_file:
                        dec_file.write(decrypted_data)

                    display_image(dec_path)
                    messagebox.showinfo("Success", f"Photo decrypted and saved as: {dec_filename}")
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            else:
                messagebox.showerror("Error", "Encrypted file not found.")

    # Function to display the decrypted photo
    def display_image(image_path):
        image_window = tk.Toplevel(main_window)
        image_window.title("Decrypted Photo")

        # Ensure the program exits when this window is closed
        image_window.protocol("WM_DELETE_WINDOW", root.destroy)

        img = Image.open(image_path)
        img = img.resize((300, 300))
        img_tk = ImageTk.PhotoImage(img)

        img_label = tk.Label(image_window, image=img_tk)
        img_label.image = img_tk
        img_label.pack()

    # Add buttons for encrypting and decrypting photos
    encrypt_button = ttk.Button(main_window, text="Encrypt Photo", command=encrypt_photo)
    encrypt_button.pack(pady=20)

    decrypt_button = ttk.Button(main_window, text="Decrypt Photo", command=decrypt_photo)
    decrypt_button.pack(pady=20)
    # Generate an encryption key
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

    # Create directories if they do not exist
    if not os.path.exists("encrypted_photos"):
        os.makedirs("encrypted_photos")
    if not os.path.exists("decrypted_photos"):
        os.makedirs("decrypted_photos")

    # Create the main application window
    main_window = tk.Toplevel(root)
    main_window.title("Photo Encryption")
    main_window.geometry("400x350+500+200")
    main_window.configure(bg="#f5f5f5")

    # Title
    title_label = tk.Label(main_window, text="Photo Encryption System", font=("Arial", 16, "bold"), bg="#f5f5f5", fg="#0078D4")
    title_label.pack(pady=15)

    # Function to encrypt the photo
    def encrypt_photo():
        file_path = filedialog.askopenfilename(title="Select a photo to encrypt", filetypes=[("Image Files", "*.jpg *.jpeg *.png")])
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    photo_data = file.read()
                    encrypted_data = cipher_suite.encrypt(photo_data)

                enc_filename = "enc_" + os.path.basename(file_path)
                enc_path = os.path.join("encrypted_photos", enc_filename)
                with open(enc_path, "wb") as enc_file:
                    enc_file.write(encrypted_data)

                messagebox.showinfo("Success", f"Photo encrypted and saved as: {enc_filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")


 # Function to decrypt the photo
    def decrypt_photo():
        enc_filename = simpledialog.askstring("Decrypt", "Enter the encrypted filename with extension")
        if enc_filename:
            file_path = os.path.join("encrypted_photos", enc_filename)
            if os.path.exists(file_path):
                try:
                    with open(file_path, "rb") as file:
                        encrypted_data = file.read()
                        decrypted_data = cipher_suite.decrypt(encrypted_data)

                    dec_filename = "dec_" + enc_filename.replace("enc_", "")
                    dec_path = os.path.join("decrypted_photos", dec_filename)
                    with open(dec_path, "wb") as dec_file:
                        dec_file.write(decrypted_data)

                    display_image(dec_path)
                    messagebox.showinfo("Success", f"Photo decrypted and saved as: {dec_filename}")
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            else:
                messagebox.showerror("Error", "Encrypted file not found.")

    # Function to display the decrypted photo
    def display_image(image_path):
        image_window = tk.Toplevel(main_window)
        image_window.title("Decrypted Photo")

        img = Image.open(image_path)
        img = img.resize((300, 300))
        img_tk = ImageTk.PhotoImage(img)

        img_label = tk.Label(image_window, image=img_tk)
        img_label.image = img_tk
        img_label.pack()

    # Add buttons for encrypting and decrypting photos
    encrypt_button = ttk.Button(main_window, text="Encrypt Photo", command=encrypt_photo)
    encrypt_button.pack(pady=20)

    decrypt_button = ttk.Button(main_window, text="Decrypt Photo", command=decrypt_photo)
    decrypt_button.pack(pady=20)

# Login UI
def login_ui():
    username = entry_username.get()
    password = entry_password.get()

    if username == "" or password == "":
        messagebox.showwarning("Input Error", "Please enter both username and password")
    elif login(username, password):
        messagebox.showinfo("Login Success", f"Welcome, {username}")
        login_window.withdraw()  # Hide the login window
        show_main_window()  # Show the main application window
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

# Registration UI
def register_ui():
    username = entry_username.get()
    password = entry_password.get()

    # Check if the password length is at least 8 characters
    if len(password) < 8:
        messagebox.showwarning("Password Error", "Password must be at least 8 characters long.")
    elif username == "" or password == "":
        messagebox.showwarning("Input Error", "Please enter both username and password")
    elif register(username, password):
        messagebox.showinfo("Registration Success", "User registered successfully!")
    else:
        messagebox.showerror("Registration Failed", "Username already exists")

# Main application root window 
root = tk.Tk()
root.title("Secure File Storage")
root.geometry("400x350+500+200")
root.withdraw()

# Ensure termination when the root window is closed
root.protocol("WM_DELETE_WINDOW", root.destroy)

# Login window
login_window = tk.Toplevel(root)
login_window.title("Login")
login_window.geometry("400x350+500+200")
login_window.configure(bg="#f5f5f5")

# Ensure termination when the login window is closed
login_window.protocol("WM_DELETE_WINDOW", root.destroy)

# Login UI elements
title_label = tk.Label(login_window, text="Login", font=("Arial", 16, "bold"), bg="#f5f5f5", fg="#0078D4")
title_label.pack(pady=15)

label_username = tk.Label(login_window, text="Username:", font=("Arial", 12), bg="#f5f5f5")
label_username.pack(pady=5)
entry_username = ttk.Entry(login_window, font=("Arial", 12))
entry_username.pack(pady=5)

label_password = tk.Label(login_window, text="Password:", font=("Arial", 12), bg="#f5f5f5")
label_password.pack(pady=5)
entry_password = ttk.Entry(login_window, show="*", font=("Arial", 12))
entry_password.pack(pady=5)

btn_login = ttk.Button(login_window, text="Login", command=login_ui)
btn_login.pack(pady=10)

btn_register = ttk.Button(login_window, text="Register", command=register_ui)
btn_register.pack(pady=5)


root.mainloop()
