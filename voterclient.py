import hashlib

from common import *

s = RSASocket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT_REGISTRAR))

while True:
    choice = raw_input('REGISTER or SIGN? > ').strip().split()
    if not len(choice) > 2:
        continue
    if not choice[0] in ['REGISTER', 'SIGN']:
        continue

    if choice[0] == "REGISTER":
        s.send(make_cmd('REGISTER', {'name': choice[1], 'password': hashlib.sha256(choice[2]).hexdigest()}))
    else:
        s.send(make_cmd('SIGN', {'name': choice[1], 'password': hashlib.sha256(choice[2]).hexdigest(), 'vote': int(choice[3])}))

    print parse_res(s.recvline())
