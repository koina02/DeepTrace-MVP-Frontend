import os
import json
import base64
import secrets
import getpass
import hashlib
import pyotp
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel

console = Console()

# Constants
KEY_VAULT_FILE = "key_vault.json"
BACKUP_FILE = "key_vault_backup.enc"
SALT_SIZE = 16
AES_KEY_SIZE = 32
IV_SIZE = 12

# Securely derive encryption key
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

# Hash master password
def hash_password(password: str) -> str:
    salt = base64.b64encode(os.urandom(SALT_SIZE)).decode()
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}${base64.b64encode(hashed).decode()}"

# Verify password
def verify_password(stored_hash: str, password: str) -> bool:
    try:
        salt, stored_hashed = stored_hash.split("$")
        computed_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
        return base64.b64encode(computed_hash).decode() == stored_hashed
    except Exception:
        return False

# Encrypt a file
def encrypt_file(filename: str, password: str):
    try:
        with open(filename, "rb") as f:
            plaintext = f.read()
        
        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        iv = os.urandom(IV_SIZE)

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        with open(filename + ".enc", "wb") as f:
            f.write(salt + iv + encryptor.tag + ciphertext)

        console.print(f"✅ File '{filename}' encrypted successfully!", style="green")
    except Exception as e:
        console.print(f"[red]Encryption failed: {e}[/red]")

# Decrypt a file
def decrypt_file(filename: str, password: str):
    try:
        with open(filename, "rb") as f:
            data = f.read()
        
        salt, iv, tag, ciphertext = data[:SALT_SIZE], data[SALT_SIZE:SALT_SIZE+IV_SIZE], data[SALT_SIZE+IV_SIZE:SALT_SIZE+IV_SIZE+16], data[SALT_SIZE+IV_SIZE+16:]
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        output_filename = filename.replace(".enc", ".dec")
        with open(output_filename, "wb") as f:
            f.write(plaintext)

        console.print(f"✅ File decrypted successfully: {output_filename}", style="green")
    except Exception as e:
        console.print(f"[red]Decryption failed: {e}[/red]")

# Generate TOTP secret
def generate_totp_secret():
    secret = pyotp.random_base32()
    console.print(f"🛡️ Your TOTP Secret (save this safely!): [yellow]{secret}[/yellow]")
    return secret

# Authenticate user with Master Password and TOTP
def authenticate_master():
    stored_hash = os.getenv("CYBERGUARD_MASTER_HASH")
    if not stored_hash:
        console.print("[red]Master password not set! Run setup first.[/red]")
        return None

    password = getpass.getpass("Enter master password: ")
    if not verify_password(stored_hash, password):
        console.print("[red]❌ Incorrect password![/red]")
        return None

    totp_secret = os.getenv("CYBERGUARD_TOTP_SECRET")
    if totp_secret:
        otp = Prompt.ask("Enter your 6-digit OTP from Google Authenticator")
        if not pyotp.TOTP(totp_secret).verify(otp):
            console.print("[red]❌ Invalid OTP![/red]")
            return None

    console.print("✅ Authentication successful!", style="green")
    return password

# Main menu
def main():
    console.print(Panel("🔐 Welcome to CyberGuard!", style="cyan"))

    if not os.getenv("CYBERGUARD_MASTER_HASH"):
        console.print("[yellow]Setting up CyberGuard for first use...[/yellow]")
        master_password = Prompt.ask("Set your master password", password=True)
        os.environ["CYBERGUARD_MASTER_HASH"] = hash_password(master_password)
        os.environ["CYBERGUARD_TOTP_SECRET"] = generate_totp_secret()
        console.print("✅ CyberGuard setup complete!", style="green")

    password = authenticate_master()
    if not password:
        return

    while True:
        console.print(Panel("🔹 CyberGuard Menu 🔹", style="blue"))
        console.print("1️⃣ Backup key vault")
        console.print("2️⃣ Restore key vault")
        console.print("3️⃣ Generate new TOTP Secret")
        console.print("4️⃣ Encrypt a File")
        console.print("5️⃣ Decrypt a File")
        console.print("6️⃣ Exit")

        choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4", "5", "6"])

        if choice == "1":
            if os.path.exists(KEY_VAULT_FILE):
                encrypt_file(KEY_VAULT_FILE, password)
                console.print(f"✅ Key vault backed up as '{BACKUP_FILE}'", style="green")
            else:
                console.print("[red]No key vault found![/red]")

        elif choice == "2":
            if os.path.exists(BACKUP_FILE):
                decrypt_file(BACKUP_FILE, password)
                console.print("✅ Key vault restored!", style="green")
            else:
                console.print("[red]No backup found![/red]")

        elif choice == "3":
            new_secret = generate_totp_secret()
            os.environ["CYBERGUARD_TOTP_SECRET"] = new_secret

        elif choice == "4":
            filename = Prompt.ask("Enter file name to encrypt")
            encrypt_file(filename, password)

        elif choice == "5":
            filename = Prompt.ask("Enter file name to decrypt")
            decrypt_file(filename, password)

        elif choice == "6":
            console.print("🔒 Exiting CyberGuard...", style="cyan")
            break

if __name__ == "__main__":
    main()
