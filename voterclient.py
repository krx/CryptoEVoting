import socket, base64, json, hashlib
from Crypto.PublicKey import RSA




s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 1337))

recvd = s.recv(2048).strip().split(',')

key = RSA.construct((long(recvd[1]), long(recvd[0])))


def encsend(inp):
    print inp
    s.send(base64.b64encode(key.encrypt(inp, 32)[0]) + '\n')
    print 'sent'

while True:
    choice = raw_input('REGISTER or SIGN? > ').strip().split()
    if not len(choice) > 2:
        continue
    if not choice[0] in ['REGISTER', 'SIGN']:
        continue

    if choice[0] == "REGISTER":
        encsend(json.dumps({'command' : 'REGISTER', 'name' : choice[1], 'password' : hashlib.sha256(choice[2]).hexdigest()}))

    else:
        encsend(json.dumps({'command' : 'SIGN', 'name' : choice[1], 'password' : hashlib.sha256(choice[2]).hexdigest(), 'vote' : choice[3]}))

    print s.recv(2048)


