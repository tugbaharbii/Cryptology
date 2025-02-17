
import os
from typing import Union
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key,
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from aes import AES  # Import AES class from aes.py

class AESCipher:
    def __init__(self, key): #şifreleme için kullanılan anahtırın uygun formatta olmasını sağlamak.
        if isinstance(key, str):
            key = bytes.fromhex(key if hasattr(key, 'hex') else key)
        
        if len(key) not in [16, 24, 32]:
            key = key[:16] if len(key) > 16 else key.ljust(16, b'\0')
        
        self.key = key
        self.aes = AES(key) 
        
    def pad(self, data): #AES yalnızca 16 baytlık bloklarla çalışır.Veri 16'nın katı değilse sonuna ekleme yapılır.
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)
        
    def unpad(self, data):#padding ile eklenen ekstra baytları kaldırır.
        pad_len = data[-1]#son byte padding uzunluğu 
        return data[:-pad_len]#veride padding çıkarır.
        
    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
            
        iv = os.urandom(16)
        padded_data = self.pad(plaintext)
        
        blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)] #blokları oluşturur.Veriyi 16 baytlık parçalara böler.
        previous = iv #ilk şifreleme bloğu için ıv kullanılır.
        ciphertext = bytearray()#şifrelenmiş veriyi tutar.
        
        for block in blocks:
            block = bytes(x ^ y for x, y in zip(block, previous)) #her blok ıv veya bir önceki şifrelenmiş bir blokla XOR işlemine tabi tutulur.
            encrypted_block = self.aes.encrypt(block) #xor sonrası aes ile şifrelenir ve sonuç ciphertext e eklenir.
            ciphertext.extend(encrypted_block)
            previous = encrypted_block
            
        return (iv + bytes(ciphertext)).hex()

    def decrypt(self, ciphertext):
        if isinstance(ciphertext, str):
            ciphertext = bytes.fromhex(ciphertext)
            
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        previous = iv
        plaintext = bytearray()
        
        for block in blocks:
            decrypted_block = self.aes.decrypt(block)
            plaintext.extend(bytes(x ^ y for x, y in zip(decrypted_block, previous)))
            previous = block
            
        return self.unpad(bytes(plaintext))


class RSAKeyManager:#amaç: RSA için anahtar çifti oluşturmak 
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, #rsa standart bir parametre 
            key_size=2048 #rsa anahtar uzunluğu
        )
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        public_pem = self.public_key.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        )
        return public_pem.decode()

    def get_private_key(self):
        private_pem = self.private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        )
        return private_pem.decode()

    @staticmethod
    def load_public_key(pem_key):
        return load_pem_public_key(pem_key.encode())

    @staticmethod
    def load_private_key(pem_key):
        return load_pem_private_key(pem_key.encode(), password=None)

    def encrypt_with_public_key(self, public_key_pem, message): #amaç genel anahtar ile şifreleme
        public_key = self.load_public_key(public_key_pem)
        encrypted = public_key.encrypt(
            message.encode() if isinstance(message, str) else message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    def decrypt_with_private_key(self, encrypted_message): # amaç özel anahtar ile çözme 
        encrypted_bytes = base64.b64decode(encrypted_message.encode())
        decrypted = self.private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

    def sign_message(self, message):#amaç: mesajları imzalama
        signature = self.private_key.sign(
            message.encode() if isinstance(message, str) else message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, message, signature, public_key_pem): # imzanın doğruluğunu kontrol etme
        public_key = self.load_public_key(public_key_pem)
        try:
            public_key.verify(
                base64.b64decode(signature.encode()),
                message.encode() if isinstance(message, str) else message,
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False