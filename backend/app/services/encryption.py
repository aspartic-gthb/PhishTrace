"""
Encryption Service for Sensitive Data
Uses Fernet (symmetric encryption) from cryptography library
"""

from cryptography.fernet import Fernet
import os
import base64
from hashlib import sha256

class EncryptionService:
    """
    Handles encryption/decryption of sensitive data like API keys
    """
    
    def __init__(self):
        # In production, store this in environment variable or KMS
        # For demo, we'll generate a key
        self.key = self._get_or_create_key()
        self.cipher = Fernet(self.key)
    
    def _get_or_create_key(self):
        """Get encryption key from file or create new one"""
        key_file = "encryption.key"
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            print("🔑 Generated new encryption key")
            return key
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string
        
        Args:
            plaintext: The text to encrypt
            
        Returns:
            Base64-encoded encrypted string
        """
        if not plaintext:
            return ""
        
        encrypted_bytes = self.cipher.encrypt(plaintext.encode())
        return encrypted_bytes.decode()
    
    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypt a string
        
        Args:
            encrypted_text: The encrypted text
            
        Returns:
            Decrypted plaintext
        """
        if not encrypted_text:
            return ""
        
        try:
            decrypted_bytes = self.cipher.decrypt(encrypted_text.encode())
            return decrypted_bytes.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return ""
    
    def rotate_key(self, old_data: list) -> tuple:
        """
        Rotate encryption key and re-encrypt data
        
        Args:
            old_data: List of encrypted strings to re-encrypt
            
        Returns:
            (new_key, re_encrypted_data)
        """
        # Decrypt with old key
        decrypted = [self.decrypt(item) for item in old_data]
        
        # Generate new key
        new_key = Fernet.generate_key()
        new_cipher = Fernet(new_key)
        
        # Re-encrypt with new key
        re_encrypted = [new_cipher.encrypt(item.encode()).decode() for item in decrypted]
        
        # Save new key
        with open("encryption.key", 'wb') as f:
            f.write(new_key)
        
        self.key = new_key
        self.cipher = new_cipher
        
        return new_key, re_encrypted


# Example usage
if __name__ == "__main__":
    enc = EncryptionService()
    
    # Test encryption
    api_key = "sk-1234567890abcdef"
    print(f"Original: {api_key}")
    
    encrypted = enc.encrypt(api_key)
    print(f"Encrypted: {encrypted}")
    
    decrypted = enc.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    assert api_key == decrypted, "Encryption/Decryption failed!"
    print("✅ Encryption working!")
