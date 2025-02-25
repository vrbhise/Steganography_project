import cv2
import numpy as np
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_message(message, passcode):
    """Encrypts the message using AES encryption with the provided passcode."""
    key = hashlib.sha256(passcode.encode()).digest()  # Generate 256-bit key from passcode
    cipher = AES.new(key, AES.MODE_CBC)  # AES in CBC mode
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))  # Encrypt and pad
    return base64.b64encode(cipher.iv + ciphertext).decode()  # Encode IV + Ciphertext

def encode_message(img, encrypted_message):
    """Hides an encrypted message inside an image using pixel encoding."""
    h, w, _ = img.shape
    max_length = (h * w * 3) - 10  # Max message length

    if len(encrypted_message) > max_length:
        raise ValueError("Message is too long for this image!")

    message = str(len(encrypted_message)).zfill(10) + encrypted_message  # Store length
    d = {chr(i): i for i in range(256)}  # ASCII to pixel mapping

    idx = 0
    for row in range(h):
        for col in range(w):
            for channel in range(3):
                if idx < len(message):
                    img[row, col, channel] = d[message[idx]]
                    idx += 1
                else:
                    return img  # Stop encoding when message is fully hidden
    return img

if __name__ == "__main__":
    image_path = "test.jpg"  # Provide the correct image path
    img = cv2.imread(image_path)

    if img is None:
        raise FileNotFoundError("Image not found! Make sure the file path is correct.")

    msg = input("Enter secret message: ")
    passcode = input("Enter a passcode: ")  # Passcode used for AES encryption

    encrypted_msg = encrypt_message(msg, passcode)
    encrypted_img = encode_message(img.copy(), encrypted_msg)

    cv2.imwrite("encryptedImage.png", encrypted_img)
    print("Message successfully encrypted and saved! Use the correct passcode to decrypt.")
