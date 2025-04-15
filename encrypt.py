from cryptography.fernet import Fernet
import os

def generate_key():
    return Fernet.generate_key()

def encrypt_file(filename, key):
    cipher = Fernet(key)
    with open(filename, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher.encrypt(file_data)
    with open(filename + ".enc", 'wb') as file:
        file.write(encrypted_data)
    print(f"Encrypted {filename} successfully.")

if __name__ == "__main__":
    filename = input("Enter file name to encrypt: ")
    if not os.path.exists(filename):
        print("File not found!")
    else:
        key = generate_key()
        encrypt_file(filename, key)
        print(f"Save this key: {key.decode()} (needed for decryption)")
