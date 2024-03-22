import socket
import random
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class Device:
    N = 8              # Size of the Secure Vault (numbers of keys)
    M = 128            # Dimension (in bit) of keys
    
    # Secure Vault
    sv = ["00100011000100110101001011100111010101110100101111010010001010011111110010010000000100000110001100001000101010010010000101010000",
            "11011010000110010101111100001100101010000100100000011010011000011101001011010110101011110110010001100000000100110100110100101000",
            "01000000100101100000110010001010111110010001010110101011111001100001011101000111010110000101100010011101011111010101111000010100",
            "11111001101101110000001010111011011111001001110101011111001111101010011100011011101011010000010100110001110110100001010011011110",
            "11110011000000110011010011001110111000001001001111101110001110011101000111110111000110110101010111010001000110100000011100001011",
            "10111100000011011001001011010101001010001011111110100000110010011100011011010101000001100010110011111101111000011000010010111011",
            "00010001011011111000110000101001011010000101010001100001101000010010000110101011110101111000100000000010111100011111011010001000",
            "01001001100111101001011111110000010100000100001010001100100001010001111111111000111101110111011011011100101110110001110000111111"]

    uid = None          # Device Unique Identifier
    session = None      # Session ID

    c1 = []             # Challenge C1
    c2 = []             # Challenge C2

    p = None

    t1 = None
    t2 = None

    r1 = None           # Random R1
    r2 = None           # Random R2

    k1 = None           # Temporary key K1

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def encrypt(self, key, plaintext):
        iv = b'\x00' * 16  # Initialization vector di lunghezza 16 byte
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        # Inizializza l'encryptor
        encryptor = cipher.encryptor()
        # Applica il padding al messaggio
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(plaintext) + padder.finalize()
        # Esegui la crittografia
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return ciphertext

    
    def decrypt(self, key, ciphertext):
        # Inizializza il cifrario AES con CBC mode
        iv = b'\x00' * 16  # Initialization vector di lunghezza 16 byte
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        # Inizializza il decryptor
        decryptor = cipher.decryptor()
        # Esegui la decrittografia
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        # Rimuovi il padding dal messaggio decrittato
        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()
        return message

    def authentication_request(self):
        self.uid = bin(random.getrandbits(32))[2:].zfill(32)
        self.session = random.getrandbits(32)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Request sent to the authentication server with message M1 containing
            # the ID of the device and the id of the session
            s.connect((self.host, self.port))
            M1 = json.dumps({'uid': self.uid, 'session': self.session}).encode()
            s.sendall(M1)

            print("\n\n--- DEVICE: Received challenge C1 --------------------------------------------\n")
            # Challenge C1 and random number R1 from Server
            data = s.recv(2048)
            decoded_data = json.loads(data.decode())  # JSON decode

            if 'c1' in decoded_data and 'r1' in decoded_data:
                self.c1 = decoded_data['c1']
                self.r1 = decoded_data['r1']
                print("Challenge C1:", self.c1)
                print("Random int R1:", self.r1)

            self.p = len(self.c1)

            print("----------------------------------------------------------------\nGeneration of random T1 and key K1\n")
            # Generation of random T1 and key K1
            self.t1 = bin(random.getrandbits(32))[2:].zfill(32)
            
            self.k1 = int(self.sv[int(self.c1[0])], 2)
            for i in range(1, len(self.c1)):
                self.k1 ^= int(self.sv[int(self.c1[i])], 2)

            # Generation of challenge C2
            for i in range(self.p):
                index = random.randint(0, self.N - 1)
                if index not in self.c2:
                    self.c2.append(index)

            # Generation of random R2
            self.r2 = random.getrandbits(32)
            print("Device generated:\nK1:", self.k1, "\nC2:", self.c2, "\nR2:", self.r2, "\nT1:", self.t1)

            rt1 = str(self.r1) + str(self.t1)
            
            M3 = json.dumps({'rt1': rt1, 'c2': self.c2, 'r2': self.r2}).encode()
            M3_enc = self.encrypt(self.k1.to_bytes(16, byteorder='big'), M3)
            print("M3 (not encrypted): ", M3)
            print("M3 encripted:", M3_enc)
            s.sendall(M3_enc)

            data = s.recv(2048)
            print("M4:", data)
            print("\n---------- RETURNED PROPERLY ----------\n\n")

if __name__ == "__main__":
    # Device configuration
    device_host = 'localhost'
    device_port = 12345
    device = Device(device_host, device_port)

    device.authentication_request()