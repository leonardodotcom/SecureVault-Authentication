import socket
import random
import sys
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class Server:
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

    p = random.randint(3, N-1)

    c1 = []
    c2 = []

    r1 = None
    r2 = None

    t1 = None
    t2 = None

    k1 = None

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


    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Socket server initialization 
            s.bind((self.host, self.port))
            s.listen()
            print("\n\nWaiting for Connections...\n")
            
            conn, addr = s.accept()
            with conn:
                print("\n--- SERVER: Connection Received -----------------------------------------------")
                # Server receives authentication request from device
                data = conn.recv(2048)
                decoded_data = json.loads(data.decode())  # JSON Decoding
                # Retrieve UID of Device and Session ID
                if 'uid' in decoded_data and 'session' in decoded_data:
                    device_uid = decoded_data['uid'].encode('utf-8')
                    session = decoded_data['session']
                
                print("Device", device_uid, "is connected with session ID:", session, "\n")

                #----------------------------------------------------------------------------------------
                
                # Check if Device's Unique Identifier is valid
                if (len(device_uid) == 32):
                    # Generation of random number r1 and challenge c1
                    self.r1 = random.getrandbits(32)

                    # Generation of challenge C1
                    for i in range(self.p):
                        index = random.randint(0, self.N - 1)
                        if index not in self.c1:
                            self.c1.append(index)

                    print("Server sent:\nR1:", self.r1, "\nC1", self.c1)
                    
                    M2 = json.dumps({'c1': self.c1, 'r1': self.r1}).encode()
                    conn.sendall(M2)

                    # Generation of key K1
                    self.k1 = int(self.sv[int(self.c1[0])], 2)
                    for i in range(1, len(self.c1)):
                        self.k1 ^= int(self.sv[int(self.c1[i])], 2)

                    print("K1:", self.k1)
                    print("\n--- Server: RECEIVED CHALLENGE C2 -----------------------------------------\n")
                    
                    data = self.decrypt(self.k1.to_bytes(16, byteorder='big'), conn.recv(2048))
                    decoded_data = json.loads(data.decode())  # Decode JSON 

                    rt1 = None
                    if 'rt1' in decoded_data and 'c2' in decoded_data and 'r2' in decoded_data:
                        rt1 = decoded_data['rt1']
                        self.c2 = decoded_data['c2']
                        self.r2 = decoded_data['r2']

                        print("Concatenated RT1:", rt1)
                        print("Challenge C2:", self.c2)
                        print("Random int R2:", self.r2)

                    if str(self.r1) in rt1:
                        print("\n\nGenerating M4\n")
                        skip = len(str(self.r1))
                        self.t1 = rt1[skip:]
                        self.t2 = bin(random.getrandbits(32))[2:].zfill(32)

                        # Generation of key K2
                        self.k2 = int(self.sv[int(self.c2[0])], 2)
                        for i in range(1, len(self.c2)):
                            self.k2 ^= int(self.sv[int(self.c2[i])], 2)
                        print("K2:", self.k2)
                        self.k2 ^= int(self.t1, 2)

                        rt2 = str(self.r2) + str(self.t2)

                        M4 = json.dumps({'rt2': rt2}).encode()
                        M4_enc = self.encrypt(self.k2.to_bytes(16, byteorder='big'), M4)
                        print("M4 (not encrypted): ", M4)
                        print("M4 encripted:", M4_enc)
                        conn.sendall(M4_enc)

                    print("\n\n---------- RETURNED PROPERLY ----------\n\n")                    

if __name__ == "__main__":
    # Device configuration
    server_host = 'localhost'
    server_port = 12345
    server = Server(server_host, server_port)

    # Starting server
    server.start_server()