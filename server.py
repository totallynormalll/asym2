import socket
import pickle

HOST = '127.0.0.1'
PORT = 8080

sock = socket.socket()
sock.bind((HOST, PORT))
sock.listen(1)
conn, addr = sock.accept()

msg = conn.recv(1024)
b = 9
p, g, A = pickle.loads(msg)
B = g ** b % p
conn.send(pickle.dumps(B))
K = A ** b % p
print("K =",K)

conn.close()