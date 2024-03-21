import socket
import random
import sys
import json

class Server:
    N = 32              # Size of the Secure Vault (numbers of keys)
    M = 32              # Dimension (in bit) of keys

    # Secure Vault of N = 32, M = 32
    SV = ["00010100010001001101100100000110","11101111101010110100100001000001","11100011111000101111000101001001", 
          "10110111010010101110111100111010","01001000111101011101101101001001","11100100000000110001010010011011",
          "11010001100010000010110000101000","10001101100001010111111001100011","00000100101001110000100110000111",
          "01101011101101100001100110100000","01101110010000000100010100101100","11111110011011011010101110100100",
          "01100110101111000101001001011011","11100111001000110110000000000001","11011110100100000010100010111111",
          "01011111001110100011010001101101","01011111111011011101101010111100","11100111111100100000111100000010",
          "10100101010101010011111100011011","00001010101001101010001110101101","01110000010110110010110110111011",
          "01010110001000000110000111011001","11000110100001101100101011110000","01011011000011110100010110111001",
          "00111001111011001101100011110100","00100010110110000100001010011010","01111000011001100000111110010001",
          "01110110110001100011000100101110","00000001011111111000000101101000","11101101001111100001011011101011",
          "10100111010010000111010010011011","01000011011101000011001110000101"]     

    p = random.randint(1, N-1)

    c1 = []
    c2 = []

    r1 = None
    r2 = None

    k1 = None

    def __init__(self, host, port):
        self.host = host
        self.port = port
        
    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print("Waiting for Connections...")
            conn, addr = s.accept()
            with conn:
                # Server receives authentication request from device
                data = conn.recv(2048)
                device_uid = int.from_bytes(data[:4], byteorder='big')
                session = int.from_bytes(data[4:], byteorder='big')
                
                print("--- Server: CONNECTION RECEIVED -----------------------------------------------\n")
                print("Device", device_uid, "is connected with session ID:", session, "\n")

                # Check if Device's Unique Identifier is valid
                if (sys.getsizeof(device_uid) == 32):
                    
                    # Generation of random number r1 and challenge c1
                    r1 = random.getrandbits(32)

                    str_c1 = ""
                    for i in range(self.p):
                        index = random.randint(0, self.N - 1)
                        if index not in self.c1:
                            self.c1.append(index)
                            str_c1 += str(index) + " "
                    M2 = json.dumps({'c1': str_c1, 'r1': r1}).encode()
                    
                    print("R1:", r1, "C1", str_c1)
                    conn.sendall(M2)

                    # Generation of key K1
                    self.k1 = int(self.sv[int(self.c1[0])])
                    self.c1 = self.c1.split()
                    for i in range(1, len(self.c1)):
                        self.k1 ^= int(self.sv[int(self.c1[0])])
                    print("K1:", self.k1, "Length:", len(str(self.k1)))


                    print("--- Server: RECEIVED CHALLENGE C2 -----------------------------------------\n")
                    data = conn.recv(2048)
                    decoded_data = json.loads(data.decode())  # Decodifica il JSON ricevuto
                    if 'rt1' in decoded_data and 'c2' in decoded_data and 'r2' in decoded_data:
                        rt1 = decoded_data['rt1']
                        self.c2 = decoded_data['c2'].split()
                        self.r2 = decoded_data['r2']

                        print("Random concatenated RT1:", rt1)
                        print("Challenge C2:", self.c2)
                        print("Random int R2:", self.r2)

if __name__ == "__main__":
    # Device configuration
    server_host = 'localhost'
    server_port = 12345
    server = Server(server_host, server_port)

    # Starting server
    server.start_server()