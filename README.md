# ACITE-PROJECT-Steganography-main
SECURE DATA HIDING IN IMAGES USING STEGANOGRAPHY 
![image](https://github.com/user-attachments/assets/57d30d7c-bf61-42ee-8f4d-e63ad3172716)

Description

The Image-Based Steganography Tool is a Python-powered application that enables users to securely hide messages within images using AES encryption and LSB (Least Significant Bit) steganography. The tool provides both encoding and decoding functionality through an intuitive Streamlit-based UI.

⭐ Features
🔐 AES Encryption: Encrypts messages using AES-CBC mode before embedding them in images.

🖼️ LSB Steganography: Hides encrypted messages in images at the pixel level.

📤 Image Upload & Download: Allows users to upload images, encode/decode messages, and download encrypted images.

🛠 User-Friendly Interface: Built with Streamlit for a seamless experience.

 Installation
 
Clone this repository:
git clone https://github.com/your-username/ACITE-PROJECT-Steganography.git
cd ACITE-PROJECT-Steganography.git

Install required dependencies:
pip install streamlit opencv-python numpy pycryptodome

Run the Application
streamlit run stego.py

Usage

🔵 Encoding a Message
Upload a PNG image.
Enter your secret message.
Provide a passcode (used for encryption & decryption).
Click Encode & Save Image.
Download the newly encrypted image.

🟢 Decoding a Message
Upload an encrypted image.
Enter the correct passcode.
Click Decode Message.
View the decrypted message.

Screenshots
Encode Message
![image](https://github.com/user-attachments/assets/c302adea-be36-4871-b5b3-b07522d6af53)

Decode Message
![image](https://github.com/user-attachments/assets/af6a2070-cda4-41f0-9c86-b3a3abda6a22)

Security Considerations
AES encryption ensures strong message protection.
Messages are not retrievable without the correct passcode.
Ensure images are stored securely to prevent unauthorized access.
👨‍💻 Technologies Used
Python 🐍

Streamlit 📊

penCV 📷

PyCryptodome 🔐

🤝 Contributing
Contributions are welcome! Feel free to fork this repository and submit a pull request.

