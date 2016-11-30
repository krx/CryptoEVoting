import hashlib

from common import *

s = RSASocket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT_REGISTRAR))

commands = {'REGISTER' : 3, 'SIGN' : 4, 'KEY' : 1, 'USER' : 2}

while True:
    choice = raw_input(', '.join(commands) + '> ').strip().split()
    if not choice[0] in commands:
        continue
    if not len(choice) == commands[choice[0]]:
        print "Invalid Number Of Arguments"
        continue

    if choice[0] == "REGISTER":
        s.send(make_cmd('REGISTER', {'name': choice[1], 'password': hashlib.sha256(choice[2]).hexdigest()}))
    elif choice[0] == 'SIGN':
        s.send(make_cmd('SIGN', {'name': choice[1], 'password': hashlib.sha256(choice[2]).hexdigest(), 'vote': int(choice[3])}))
    elif choice[0] == 'KEY':
        s.send(make_cmd('KEY'), {})
    elif choice[0] == 'USER':
        s.send(make_cmd('USER', {'name': choice[1]}))
    print parse_res(s.recvline().strip())
