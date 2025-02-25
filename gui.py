import cv2
import numpy as np
import base64
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES Encryption
def encrypt_message(message, passcode):
    key = hashlib.sha256(passcode.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode()

# AES Decryption
def decrypt_message(encrypted_message, passcode):
    key = hashlib.sha256(passcode.encode()).digest()
    encrypted_data = base64.b64decode(encrypted_message)
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# Encoding the message into an image
def encode_message(img, encrypted_message):
    h, w, _ = img.shape
    max_length = (h * w * 3) - 10

    if len(encrypted_message) > max_length:
        raise ValueError("Message is too long for this image!")

    message = str(len(encrypted_message)).zfill(10) + encrypted_message
    d = {chr(i): i for i in range(256)}

    idx = 0
    for row in range(h):
        for col in range(w):
            for channel in range(3):
                if idx < len(message):
                    img[row, col, channel] = d[message[idx]]
                    idx += 1
                else:
                    return img
    return img

# Decoding the hidden message from an image
def decode_message(img):
    h, w, _ = img.shape
    c = {i: chr(i) for i in range(256)}

    idx = 0
    extracted_length = ""
    extracted_message = ""
    message_length = 0

    for row in range(h):
        for col in range(w):
            for channel in range(3):
                pixel_value = img[row, col, channel]
                char = c.get(pixel_value, '?')

                if idx < 10:
                    extracted_length += char
                idx += 1

                if idx == 10:
                    try:
                        message_length = int(extracted_length.strip())
                    except ValueError:
                        return "Error: Invalid encrypted data. Ensure the correct image is used."
                elif idx > 10 and idx <= 10 + message_length:
                    extracted_message += char

                if idx > 10 + message_length:
                    return extracted_message.strip()

    return "Error: Message could not be fully extracted."

# GUI Functions
def encrypt_and_hide():
    file_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    
    if not file_path:
        return
    
    img = cv2.imread(file_path)
    if img is None:
        messagebox.showerror("Error", "Invalid image file!")
        return
    
    message = message_entry.get()
    passcode = passcode_entry.get()

    if not message or not passcode:
        messagebox.showwarning("Warning", "Message and Passcode cannot be empty!")
        return

    try:
        encrypted_msg = encrypt_message(message, passcode)
        encrypted_img = encode_message(img.copy(), encrypted_msg)
        save_path = "encryptedImage.png"
        cv2.imwrite(save_path, encrypted_img)
        messagebox.showinfo("Success", f"Message encrypted & saved as {save_path}")
        
        # Clear input fields after encryption
        message_entry.delete(0, tk.END)
        passcode_entry.delete(0, tk.END)
    
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_and_show():
    file_path = filedialog.askopenfilename(title="Select Encrypted Image", filetypes=[("Image Files", "*.png")])
    
    if not file_path:
        return

    encrypted_img = cv2.imread(file_path)
    if encrypted_img is None:
        messagebox.showerror("Error", "Invalid image file!")
        return

    passcode = passcode_entry.get()

    if not passcode:
        messagebox.showwarning("Warning", "Passcode cannot be empty!")
        return

    try:
        encrypted_message = decode_message(encrypted_img)

        if encrypted_message.startswith("Error"):
            messagebox.showerror("Error", encrypted_message)
        else:
            try:
                decrypted_message = decrypt_message(encrypted_message, passcode)
                messagebox.showinfo("Decryption Successful!", f"Decrypted Message: {decrypted_message}")
                
                # Clear input field after decryption
                passcode_entry.delete(0, tk.END)
            
            except ValueError:
                messagebox.showerror("Error", "Incorrect passcode or corrupted data.")
    
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
root = tk.Tk()
root.title("Image Steganography with AES")
root.geometry("400x350")
root.configure(bg="#f4f4f4")

# UI Elements
title_label = tk.Label(root, text="🔐 Secure Image Steganography", font=("Arial", 14, "bold"), bg="#f4f4f4")
title_label.pack(pady=10)

message_label = tk.Label(root, text="Secret Message:", bg="#f4f4f4")
message_label.pack()
message_entry = tk.Entry(root, width=40)
message_entry.pack(pady=5)

passcode_label = tk.Label(root, text="Passcode:", bg="#f4f4f4")
passcode_label.pack()
passcode_entry = tk.Entry(root, width=40, show="*")  # Hide passcode input
passcode_entry.pack(pady=5)

encrypt_button = tk.Button(root, text="Encrypt & Hide", command=encrypt_and_hide, bg="#008CBA", fg="white")
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt & Reveal", command=decrypt_and_show, bg="#4CAF50", fg="white")
decrypt_button.pack(pady=5)

exit_button = tk.Button(root, text="Exit", command=root.quit, bg="red", fg="white")
exit_button.pack(pady=10)

# Run the GUI
root.mainloop()
