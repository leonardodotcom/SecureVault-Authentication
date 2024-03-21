import socket
import random
import json

class Device:
    N = 32              # Size of the Secure Vault (numbers of keys)
    M = 32              # Dimension (in bit) of keys
    
    # Secure Vault of N = 32, M = 32
    sv = ["00010100010001001101100100000110","11101111101010110100100001000001","11100011111000101111000101001001", 
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

    uid = None          # Device Unique Identifier
    session = None      # Session ID

    c1 = []             # Challenge C1
    c2 = []             # Challenge C2

    r1 = None           # Random R1
    r2 = None           # Random R2

    k1 = None           # Temporary key K1

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def authentication_request(self):
        self.uid = random.getrandbits(32)
        self.session = random.getrandbits(32)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Request sent to the authentication server with message M1 containing
            # the ID of the device and the id of the session
            s.connect((self.host, self.port))
            M1 = self.uid.to_bytes(4, byteorder='big') + self.session.to_bytes(4, byteorder='big')
            s.sendall(M1)

            print("--- Device: RECEIVED CHALLENGE C1 --------------------------------------------\n")
            # Receive Challenge C1 and random number R1 from Server
            data = s.recv(2048)
            decoded_data = json.loads(data.decode())  # Decodifica il JSON ricevuto
            if 'c1' in decoded_data and 'r1' in decoded_data:
                self.c1 = decoded_data['c1']
                self.r1 = decoded_data['r1']

                print("Challenge C1:", self.c1)
                print("Random int R1:", self.r1)

            print("Generation of random T1 and key K1")
            # Generation of random T1 and key K1
            t1 = random.getrandbits(32)

            self.k1 = int(self.sv[int(self.c1[0])])
            self.c1 = self.c1.split()
            for i in range(1, len(self.c1)):
                self.k1 ^= int(self.sv[int(self.c1[0])])

            print("T1:", t1, "\nK1:", self.k1, "Length:", len(str(self.k1)))
            
            print("Generation of challenge C2, concatenation of R1 and T1, random number R2")
            # Generation of Challenge C2
            str_c2 = ""
            for i in range(len(self.c1)):
                index = random.randint(0, self.N - 1)
                if index not in self.c2:
                    self.c2.append(index)
                    str_c2 += str(index) + " "

            rt1 = str(self.r1) + str(t1)
            r2 = random.getrandbits(32)

            print("C2:", str_c2, "\nR1:", self.r1, "\nRT1:", rt1, "\nR2:", r2)

            M3 = json.dumps({'rt1': rt1, 'c2': str_c2, 'r2': r2}).encode()
            s.sendall(M3)


if __name__ == "__main__":
    # Device configuration
    device_host = 'localhost'
    device_port = 12345
    device = Device(device_host, device_port)

    device.authentication_request()