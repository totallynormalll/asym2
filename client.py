import socket
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = '127.0.0.1'
PORT = 8080

# Diffie-Hellman parameters
p, g, a = 7, 5, 3
A = g ** a % p

# Connect to server
sock = socket.socket()
sock.connect((HOST, PORT))

# Send Diffie-Hellman parameters and A to the server
sock.send(pickle.dumps((p, g, A)))

# Receive B from the server
msg = sock.recv(1024)
B = pickle.loads(msg)

# Calculate the shared secret K
K = B ** a % p
print("Shared secret K =", K)

# Receive the server's public key (PEM format)
msg = sock.recv(1024)
public_key_pem = pickle.loads(msg)

# Import the public key from PEM format
server_public_key = RSA.import_key(public_key_pem)

# Encrypt a message using the server's public key
message = "Hello, server!"
encryptor = PKCS1_OAEP.new(server_public_key)
encrypted_message = encryptor.encrypt(message.encode())

# Send the encrypted message to the server
sock.send(pickle.dumps(encrypted_message))

sock.close()