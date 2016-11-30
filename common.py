"""
Common variables/utilities shared between services
"""
import base64
import json
import socket
from SocketServer import StreamRequestHandler

from Crypto.PublicKey import RSA

HOST = 'localhost'
PORT_REGISTRAR = 9001
PORT_BOARD = 9002


class CommandHandler(StreamRequestHandler):
    def __init__(self, request, client_address, server):
        self.running = True
        self.commands = {'quit': lambda _: setattr(self, 'running', False)}
        self.init_commands()
        StreamRequestHandler.__init__(self, request, client_address, server)

    def init_commands(self):
        raise NotImplementedError('Define commands for this handler')

    def println(self, s=''):
        self.wfile.write('{}\n'.format(s))

    def input(self, prompt=''):
        self.wfile.write(prompt)
        return self.rfile.readline().rstrip('\r\n')

    def process_cmd(self):
        try:
            cmd = json.loads(self.input())
            assert 'command' in cmd and 'args' in cmd
            res = self.commands[cmd['command']](cmd['args'])
            self.println(json.dumps({'res': res}))
        except:
            self.println('Invalid input')

    def handle(self):
        while self.running:
            self.process_cmd()


class Socket(socket.socket):
    def __init__(self, family=socket.AF_INET, stype=socket.SOCK_STREAM, proto=0, _sock=None):
        socket.socket.__init__(self, family, stype, proto, _sock)

        # For usage by overriding sends
        self.raw_send = self.send

    def recvline(self):
        buf = self.recv(1)
        while buf[-1] != '\n':
            buf += self.recv(1)
        return buf

    def sendline(self, data):
        self.send('{}\n'.format(str(data)))


class RSACommandHandler(CommandHandler):
    # Shared across all handlers in this process
    rsa_key = RSA.generate(2048)

    def __init__(self, request, client_address, server):
        CommandHandler.__init__(self, request, client_address, server)

    def input(self, prompt=''):
        enc = CommandHandler.input(self, prompt)
        return self.rsa_key.decrypt(base64.b64decode(enc))

    def handle(self):
        # Send the public key
        self.println(json.dumps({'n': self.rsa_key.n, 'e': self.rsa_key.e}))
        CommandHandler.handle(self)


class RSASocket(Socket):
    def __init__(self, family=socket.AF_INET, stype=socket.SOCK_STREAM, proto=0, _sock=None):
        Socket.__init__(self, family, stype, proto, _sock)
        self.rsa_pub_key = None

        # override the regular send with the encrypted version
        self.send = self.encsend

    def connect(self, addr):
        # Open the connection
        Socket.connect(self, addr)

        # Receive and load the public key
        pub = json.loads(self.recvline())
        self.rsa_pub_key = RSA.construct((long(pub['n']), long(pub['e'])))

    def encsend(self, data):
        self.raw_send(base64.b64encode(self.rsa_pub_key.encrypt(data, 32)[0]) + '\n')


def make_cmd(cmd, args=None):
    return json.dumps({
        'command': cmd.lower(),
        'args': args or {}
    })
