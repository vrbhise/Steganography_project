import cv2
import numpy as np
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_message(encrypted_message, passcode):
    """Decrypts an AES-encrypted message using the provided passcode."""
    key = hashlib.sha256(passcode.encode()).digest()  # Generate 256-bit key from passcode
    encrypted_data = base64.b64decode(encrypted_message)  # Decode base64
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]  # Extract IV and ciphertext

    cipher = AES.new(key, AES.MODE_CBC, iv)  # AES in CBC mode
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()  # Decrypt and remove padding

def decode_message(img):
    """Extracts and returns the hidden encrypted message from an image."""
    h, w, _ = img.shape
    c = {i: chr(i) for i in range(256)}  # Pixel value to ASCII mapping

    idx = 0
    extracted_length = ""
    extracted_message = ""
    message_length = 0  # Default message length

    for row in range(h):
        for col in range(w):
            for channel in range(3):
                pixel_value = img[row, col, channel]
                char = c.get(pixel_value, '?')

                if idx < 10:  # Extract first 10 characters (message length)
                    extracted_length += char
                idx += 1

                if idx == 10:  # Convert extracted length to an integer
                    try:
                        message_length = int(extracted_length.strip())
                    except ValueError:
                        return "Error: Invalid encrypted data. Ensure the correct image is used."
                elif idx > 10 and idx <= 10 + message_length:
                    extracted_message += char

                if idx > 10 + message_length:
                    return extracted_message.strip()  # Stop reading at correct message length

    return "Error: Message could not be fully extracted."

if __name__ == "__main__":
    image_path = "encryptedImage.png"  # Use PNG to avoid compression issues
    encrypted_img = cv2.imread(image_path)

    if encrypted_img is None:
        raise FileNotFoundError("Encrypted image not found! Make sure it was saved correctly.")

    passcode = input("Enter passcode for decryption: ")
    correct_passcode = input("Re-enter the passcode used for encryption: ")

    if passcode == correct_passcode:
        encrypted_message = decode_message(encrypted_img)
        if encrypted_message.startswith("Error"):
            print(encrypted_message)
        else:
            try:
                decrypted_message = decrypt_message(encrypted_message, passcode)
                print("Decryption successful! Message:", decrypted_message)
            except ValueError:
                print("Decryption failed. Incorrect passcode or corrupted data.")
    else:
        print("Incorrect passcode. Decryption failed.")
