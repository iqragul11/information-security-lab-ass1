# Caesar Cipher Program
# Course: Information Security
# This program encrypts and decrypts a message using Caesar Cipher

# Function for Encryption
def caesar_encrypt(text, shift):
    result = ""

    for char in text:
        # Check if character is uppercase letter
        if char.isupper():
            # Convert to ASCII, shift, and convert back
            result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))

        # Check if character is lowercase letter
        elif char.islower():
            result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))

        # Keep spaces and special characters unchanged
        else:
            result += char

    return result


# Function for Decryption
def caesar_decrypt(ciphertext, shift):
    result = ""

    for char in ciphertext:
        if char.isupper():
            result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))

        elif char.islower():
            result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))

        else:
            result += char

    return result


# Example Usage
if __name__ == "__main__":
    message = "Hi Im here ! Information Security"
    shift_value = 3

    encrypted = caesar_encrypt(message, shift_value)
    decrypted = caesar_decrypt(encrypted, shift_value)

    print("Original Message :", message)
    print("Encrypted Message:", encrypted)
    print("Decrypted Message:", decrypted)