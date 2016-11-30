import socket, base64
from Crypto.PublicKey import RSA




s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 1337))

recvd = s.recv(2048).strip().split(',')

key = RSA.construct((long(recvd[1]), long(recvd[0])))


while True:
    s.send(base64.b64encode(key.encrypt(raw_input("> "), 32)[0]) + '\n')

    print s.recv(2048)


