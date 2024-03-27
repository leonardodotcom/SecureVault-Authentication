import socket
import random
import json

import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class Device:
    N = 8              # Size of the Secure Vault (numbers of keys)
    M = 128            # Dimension (in bit) of each keys
    
    # Secure Vault
    sv = ["00100011000100110101001011100111010101110100101111010010001010011111110010010000000100000110001100001000101010010010000101010000",
            "11011010000110010101111100001100101010000100100000011010011000011101001011010110101011110110010001100000000100110100110100101000",
            "01000000100101100000110010001010111110010001010110101011111001100001011101000111010110000101100010011101011111010101111000010100",
            "11111001101101110000001010111011011111001001110101011111001111101010011100011011101011010000010100110001110110100001010011011110",
            "11110011000000110011010011001110111000001001001111101110001110011101000111110111000110110101010111010001000110100000011100001011",
            "10111100000011011001001011010101001010001011111110100000110010011100011011010101000001100010110011111101111000011000010010111011",
            "00010001011011111000110000101001011010000101010001100001101000010010000110101011110101111000100000000010111100011111011010001000",
            "01001001100111101001011111110000010100000100001010001100100001010001111111111000111101110111011011011100101110110001110000111111"]

    uid = None              # Device Unique Identifier
    session = None          # Session ID

    c1 = []                 # Challenge C1
    c2 = []                 # Challenge C2

    t1 = None               # Temporary key T1
    t2 = None               # Temporary key T2

    r1 = None               # Random number R1
    r2 = None               # Random number R2

    k1 = None               # Temporary key K1

    def __init__(self, host, port):
        self.uid = bin(random.getrandbits(32))[2:].zfill(32)
        self.host = host
        self.port = port

    def update_sv(self, data_exchanged):
        secure_vault_bytes = ''.join(self.sv).encode('utf-8')
        hash = int.from_bytes(bytes.fromhex(hashlib.md5(data_exchanged + secure_vault_bytes).hexdigest()), byteorder='big')
        hash_length = len(bin(hash)[2:].zfill(self.M))

        sv_to_string = ""
        for i in range(len(self.sv)):
            sv_to_string += self.sv[i]

        r = len(sv_to_string) % hash_length
        if r != 0:
            padding_length = (hash_length - r) % hash_length
            sv_to_string = sv_to_string + '0' * padding_length 

        cursor = 0
        self.sv = ""
        for i in range(len(sv_to_string) // hash_length):
            partition = hash ^ int(sv_to_string[cursor:cursor + hash_length], 2)
            self.sv += bin(partition)[2:].zfill(128)
            cursor += hash_length

        self.sv = [self.sv[i:i+128] for i in range(0, len(self.sv), 128)]

    def encrypt(self, key, plaintext):
        # Initialization vector and AES cipher
        iv = b'\x00' * 16  
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        # Initialize the encryptor
        encryptor = cipher.encryptor()
        # Apply padding to the message
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(plaintext) + padder.finalize()
        # Execute cryptography
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return ciphertext
    
    def decrypt(self, key, ciphertext):
        # Initialization vector and the AES cipher
        iv = b'\x00' * 16
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        # Initialize the decryptor
        decryptor = cipher.decryptor()
        # Execute decryption
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()
        return message

    def authentication_request(self):
        # Generating session number
        self.session = random.getrandbits(32)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Request sent to the authentication server with message M1 containing
            # the ID of the device and the id of the session
            s.connect((self.host, self.port))
            M1 = json.dumps({'uid': self.uid, 'session': self.session}).encode()
            s.sendall(M1)
            print("\nDEVICE", self.uid, "sent to the Server the message M1: UID", self.uid, "- Session", self.session)
            # Storing the exchanged data
            session_data = self.uid + bin(self.session)[2:]

#-------------------------------------------------------------------------------------------

            print("\nDEVICE", self.uid, "received challenge message M2 with C1 and R1")
            # Challenge C1 and random number R1 from Server
            data = s.recv(2048)
            decoded_data = json.loads(data.decode())  # JSON decode

            if 'c1' in decoded_data and 'r1' in decoded_data:
                self.c1 = decoded_data['c1']
                self.r1 = decoded_data['r1']
                print("Challenge C1:", self.c1)
                print("Random integer R1:", self.r1)

                # Storing the exchanged data
                for num in self.c1:
                    session_data += bin(num)[2:]
                session_data += bin(self.r1)[2:]

            # Generation of random T1
            self.t1 = bin(random.getrandbits(self.M))[2:].zfill(self.M)
            # Generation of key K1
            self.k1 = int(self.sv[int(self.c1[0])], 2)
            for i in range(1, len(self.c1)):
                self.k1 ^= int(self.sv[int(self.c1[i])], 2)
            # Generation of challenge C2
            for i in range(len(self.c1)):
                index = random.randint(0, self.N - 1)
                if index not in self.c2:
                    self.c2.append(index)
            # Generation of random R2
            self.r2 = random.getrandbits(32)
            # Concatenation of R1 and T1
            rt1 = str(self.r1) + str(self.t1)
            
            # Sending to the server the message M3 composed of:
            # concatenated R1 and T1 with RT1, Challenge C2 and random number R2
            M3 = json.dumps({'rt1': rt1, 'c2': self.c2, 'r2': self.r2}).encode()
            M3_enc = self.encrypt(self.k1.to_bytes(16, byteorder='big'), M3)
            s.sendall(M3_enc)
            
            # Storing the exchanged data
            session_data += bin(self.r1)[2:] + self.t1
            for num in self.c2:
                session_data += bin(num)[2:]
            session_data += bin(self.r2)[2:]

            print("\nDEVICE", self.uid, "sent to the Server the message M3: RT1", rt1, "- C2", self.c2, "- R2", self.r2)
            print("- M3 [not encrypted]:\n", M3)
            print("- M3 [encripted]:\n", M3_enc)
            
#-------------------------------------------------------------------------------------------
            
            # Generation of key K2
            self.k2 = int(self.sv[int(self.c2[0])], 2)
            for i in range(1, len(self.c2)):
                self.k2 ^= int(self.sv[int(self.c2[i])], 2)
            self.k2 ^= int(self.t1, 2)

#-------------------------------------------------------------------------------------------

            # Receiving of message M4 from Server
            data = self.decrypt(self.k2.to_bytes(16, byteorder='big'), s.recv(2048))
            decoded_data = json.loads(data.decode())  # Decode JSON 

            # Variable for storing the concatenation of R2 and T2
            rt2 = None
            if 'rt2' in decoded_data:
                rt2 = decoded_data['rt2']

            print("\nDEVICE", self.uid, "received message M4 with\n- RT2", rt2)

            # Verification of the identity of R2 by retrieving R2 from M4
            if str(self.r2) in rt2:
                skip = len(str(self.r2))
                self.t2 = rt2[skip:]

                # Casting of T1 and T2 to integer to perform XOR operation
                converted_t1 = int(self.t1, 2)
                converted_t2 = int(self.t2, 2)

                self.t = bin(converted_t1 ^ converted_t2)[2:].zfill(128)

                # Storing the exchanged data
                session_data += bin(self.r2)[2:] + self.t2

                print("\nFinal key T:", int(self.t, 2), "of length", len((self.t)), "bit\n")      

            self.update_sv(bytes(session_data.encode('utf-8')))
            print("The updated secure vault:", self.sv, "\n")

if __name__ == "__main__":
    # Device configuration
    device_host = 'localhost'
    device_port = 12345
    device = Device(device_host, device_port)
    # Initialize request of authentication to the server
    device.authentication_request()