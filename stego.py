import streamlit as st
import cv2
import numpy as np
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import tempfile

def hash_password(password):
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode()).digest()

def encrypt_message(message, password):
    """Encrypts the message using AES encryption."""
    key = hash_password(password)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + encrypted).decode()

def decrypt_message(encrypted_message, password):
    """Decrypts the AES encrypted message."""
    key = hash_password(password)
    data = base64.b64decode(encrypted_message)
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        return unpad(cipher.decrypt(encrypted), AES.block_size).decode()
    except:
        return "Unable to retrieve message. Incorrect password or corrupted data."

def encode_message(img, message, password):
    """Encodes an encrypted message into an image using LSB."""
    encrypted_message = encrypt_message(message, password) + "%%"
    binary_message = ''.join(format(ord(c), '08b') for c in encrypted_message)
    img_flat = img.flatten()
    
    if len(binary_message) > len(img_flat):
        return None, "Message is too long for this image!"
    
    for i in range(len(binary_message)):
        img_flat[i] = (img_flat[i] & 254) | int(binary_message[i])  # ✅ Safe uint8 assignment
    
    img_encoded = img_flat.reshape(img.shape)
    return img_encoded, "Message encrypted successfully!"

def decode_message(img, password):
    """Extracts and decrypts the hidden message from an image."""
    img_flat = img.flatten()
    binary_message = ''.join(str(img_flat[i] & 1) for i in range(len(img_flat)))
    chars = [chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8)]
    extracted_message = ''.join(chars)
    
    if "%%" not in extracted_message:
        return "No hidden message found."
    
    extracted_message = extracted_message.split("%%")[0]
    return decrypt_message(extracted_message, password)

# Streamlit UI
st.title("🔒 Image-Based Steganography Tool")
option = st.radio("Select an option", ("Encode Message", "Decode Message"))

if option == "Encode Message":
    uploaded_file = st.file_uploader("Upload an Image (PNG only)", type=["png"])
    if uploaded_file:
        image = cv2.imdecode(np.frombuffer(uploaded_file.read(), np.uint8), cv2.IMREAD_UNCHANGED)
        if image.shape[2] == 4:  # Convert to RGB if image has an alpha channel
            image = cv2.cvtColor(image, cv2.COLOR_BGRA2BGR)
        st.image(image, caption="Uploaded Image", use_column_width=True)
        
        message = st.text_area("Enter your secret message")
        password = st.text_input("Enter passcode", type="password")
        
        max_message_length = (image.shape[0] * image.shape[1] * image.shape[2]) // 8
        st.write(f"Max message length: {max_message_length} characters")
        
        if st.button("Encode & Save Image"):
            if len(message) > max_message_length:
                st.error(f"Message too long! Max length: {max_message_length} characters.")
            else:
                encoded_img, status = encode_message(image, message, password)
                if encoded_img is not None:
                    temp_dir = tempfile.gettempdir()
                    file_path = os.path.join(temp_dir, "encoded_image.png")
                    cv2.imwrite(file_path, encoded_img)
                    st.success(status)
                    with open(file_path, "rb") as file:
                        st.download_button("Download Encrypted Image", file, "encoded_image.png")
                else:
                    st.error(status)

elif option == "Decode Message":
    uploaded_file = st.file_uploader("Upload an Encrypted Image", type=["png"])
    if uploaded_file:
        image = cv2.imdecode(np.frombuffer(uploaded_file.read(), np.uint8), cv2.IMREAD_COLOR)
        st.image(image, caption="Uploaded Encrypted Image", use_column_width=True)
        password = st.text_input("Enter passcode", type="password")
        if st.button("Decode Message"):
            decrypted_message = decode_message(image, password)
            st.success(f"Decrypted Message: {decrypted_message}")
