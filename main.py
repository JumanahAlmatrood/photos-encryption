import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.fernet import Fernet
from PIL import Image, ImageTk
import os

# Generate an encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Create directories if they do not exist
if not os.path.exists("encrypted_photos"):
    os.makedirs("encrypted_photos")

if not os.path.exists("decrypted_photos"):
    os.makedirs("decrypted_photos")

# Create the tkinter window
window = tk.Tk()
window.title("Photo Encryption")

# Function to encrypt the photo
def encrypt_photo():
    file_path = filedialog.askopenfilename(title="Select a photo to encrypt", filetypes=[("Image Files", "*.jpg *.jpeg *.png")])
    if file_path:
        try:
            # Read and encrypt the photo data
            with open(file_path, "rb") as file:
                photo_data = file.read()
                encrypted_data = cipher_suite.encrypt(photo_data)

            # Save the encrypted photo
            enc_filename = "enc_" + os.path.basename(file_path)
            enc_path = os.path.join("encrypted_photos", enc_filename)
            with open(enc_path, "wb") as enc_file:
                enc_file.write(encrypted_data)

            messagebox.showinfo("Success", f"The photo has been encrypted and saved as: {enc_filename}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")

# Function to decrypt the photo
def decrypt_photo():
    # Request the filename from the user
    enc_filename = simpledialog.askstring("Decrypt", "Enter the encrypted filename (without path)")
    if enc_filename:
        file_path = os.path.join("encrypted_photos", enc_filename)
        if os.path.exists(file_path):
            try:
                # Read and decrypt the photo data
                with open(file_path, "rb") as file:
                    encrypted_data = file.read()
                    decrypted_data = cipher_suite.decrypt(encrypted_data)

                # Save the decrypted photo
                dec_filename = "dec_" + enc_filename.replace("enc_", "")
                dec_path = os.path.join("decrypted_photos", dec_filename)
                with open(dec_path, "wb") as dec_file:
                    dec_file.write(decrypted_data)

                # Display the photo
                display_image(dec_path)

                messagebox.showinfo("Success", f"The photo has been decrypted and saved as: {dec_filename}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")
        else:
            messagebox.showerror("Error", "File not found. Please check the filename and try again.")

# Function to display the photo in a new window
def display_image(image_path):
    image_window = tk.Toplevel(window)
    image_window.title("Decrypted Photo")

    # Open and display the photo
    img = Image.open(image_path)
    img = img.resize((300, 300))  # Resize if needed
    img_tk = ImageTk.PhotoImage(img)

    img_label = tk.Label(image_window, image=img_tk)
    img_label.image = img_tk
    img_label.pack()

# Add buttons to the interface
encrypt_button = tk.Button(window, text="Encrypt Photo", command=encrypt_photo)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(window, text="Decrypt Photo", command=decrypt_photo)
decrypt_button.pack(pady=10)

# Run the tkinter window
window.mainloop()
