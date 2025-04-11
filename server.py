import socket
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = '127.0.0.1'
PORT = 8080

# Diffie-Hellman parameters
sock = socket.socket()
sock.bind((HOST, PORT))
sock.listen(1)
conn, addr = sock.accept()

# Receive Diffie-Hellman parameters and A from the client
msg = conn.recv(1024)
b = 9
p, g, A = pickle.loads(msg)

# Compute B and send it to the client
B = g ** b % p
conn.send(pickle.dumps(B))

# Calculate the shared secret K
K = A ** b % p
print("Shared secret K =", K)

# Generate the RSA public/private key pair
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# Export the public key to PEM format (bytes)
public_key_pem = public_key.export_key()

# Send the PEM-encoded public key to the client
conn.send(pickle.dumps(public_key_pem))

# Receive and decrypt the message from the client
msg = conn.recv(1024)
encrypted_message = pickle.loads(msg)

decryptor = PKCS1_OAEP.new(private_key)
decrypted_message = decryptor.decrypt(encrypted_message)

print(f"Decrypted message: {decrypted_message.decode()}")

conn.close()