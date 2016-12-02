"""
Common variables/utilities shared between services
"""
import base64
import hashlib
import json
import socket
import traceback
from SocketServer import StreamRequestHandler

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import AESHelper

# Network constants
HOST = 'localhost'
PORT_REGISTRAR = 9001
PORT_BOARD = 9002

# Common # of rounds in ZKP
ZKP_ROUNDS = 5


class CommandHandler(StreamRequestHandler):
    """
    Handler template for a command-based service

    To define commands, you need to override init_commands():
        To define a command, you call add_cmd and pass:
        - the command name (case insensitive)
        - a function that takes a single dict argument
    That's it, once commands are received the functions you defined will be called

    Any commands that are received are expected to be in the JSON format:
    {
        "command": "command name",
        "args": {
            "any": "arguments",
            "go": "here"
        }
    }

    The response will be in the format:
    {"res": "Response goes here"}
    """

    def __init__(self, request, client_address, server):
        self.running = True
        self.commands = {}

        self.add_cmd('quit', lambda _: setattr(self, 'running', False))
        self.init_commands()

        StreamRequestHandler.__init__(self, request, client_address, server)

    def init_commands(self):
        raise NotImplementedError('Define commands for this handler')

    def add_cmd(self, cmd, func):
        self.commands[cmd.upper()] = func

    def println(self, s=''):
        self.wfile.write('{}\n'.format(s))

    def input(self, prompt=''):
        self.wfile.write(prompt)
        return self.rfile.readline().rstrip('\r\n')

    def salt(self, password):
        return 'whyso' + password + 'salty'

    def process_cmd(self):
        try:
            cmd = json.loads(self.input())
            print cmd
            assert 'command' in cmd and 'args' in cmd
            if 'password' in cmd['args']:
                cmd['args']['password'] = hashlib.sha256(self.salt(cmd['args']['password'])).hexdigest()
            res = self.commands[cmd['command']](cmd['args'])
            self.println(make_res(res))
        except:
            print traceback.format_exc()
            self.println(make_res('Options: {}'.format(', '.join(self.commands.keys()))))

    def handle(self):
        while self.running:
            self.process_cmd()


class Socket(socket.socket):
    """
    Little extension to sockets to add some convenient functions
    """

    def __init__(self, family=socket.AF_INET, stype=socket.SOCK_STREAM, proto=0, _sock=None):
        socket.socket.__init__(self, family, stype, proto, _sock)

        # For usage by overriding sends
        self.raw_send = self.send

    def recvline(self):
        """ Reads from the buffer until a newline ('\n') is found
        This will block until it reads in a newline

        Returns:
            str: The line that was read, including the newline
        """
        buf = self.recv(1)
        while buf[-1] != '\n':
            buf += self.recv(1)
        return buf

    def sendline(self, data):
        """ Sends a string of data over the socket, ending it with a newline

        Args:
            data (Any): What to print to the socket
        """
        self.send('{}\n'.format(str(data)))


class SecureCommandHandler(CommandHandler):
    """
    A CommandHandler that encrypts traffic using AES
    """

    # Shared across all handlers in this process
    rsa_key = RSA.generate(2048)

    def __init__(self, request, client_address, server):
        self.aes_iv = None
        self.aes_key = None
        CommandHandler.__init__(self, request, client_address, server)

    def input(self, prompt=''):
        # Read in the encrypted data and decrypt it before returning
        enc = CommandHandler.input(self, prompt)
        return AESHelper.decrypt(base64.b64decode(enc), self.aes_key, self.aes_iv)

    def handle(self):
        # Send the public key to the client
        self.println(json.dumps({'n': self.rsa_key.n, 'e': self.rsa_key.e}))

        # Get the encrypted AES iv/key
        aes_data = self.rsa_key.decrypt(base64.b64decode(CommandHandler.input(self)))
        self.aes_iv, self.aes_key = aes_data[:AES.block_size], aes_data[AES.block_size:]

        # Continue with the handler as usual
        CommandHandler.handle(self)


class SecureSocket(Socket):
    """
    An extension to Socket that encrypts traffic with AES
    """

    def __init__(self, family=socket.AF_INET, stype=socket.SOCK_STREAM, proto=0, _sock=None):
        Socket.__init__(self, family, stype, proto, _sock)

        # Generate AES iv/key
        self.aes_iv = get_random_bytes(AES.block_size)
        self.aes_key = get_random_bytes(AES.block_size * 2)

        # override the regular send with the encrypted version
        # We have to do it this way because socket.__init__ overwrites the 'send' attribute
        # So this "fixes" that
        self.send = self.encsend

    def connect(self, addr):
        # Open the connection
        Socket.connect(self, addr)

        # Receive and load the public key
        pub = json.loads(self.recvline())
        rsa_pub_key = RSA.construct((long(pub['n']), long(pub['e'])))

        # Send the encrypted AES iv/key
        self.raw_send(base64.b64encode(rsa_pub_key.encrypt(self.aes_iv + self.aes_key, 32)[0]) + '\n')

    def encsend(self, data):
        # Encrypt the data with AES before sending
        self.raw_send(base64.b64encode(AESHelper.encrypt(data, self.aes_key, self.aes_iv)) + '\n')


# Command util functions
def make_cmd(cmd, args=None):
    # type: (str, dict) -> str
    # Helper to create a formatted command string from a name/args
    return json.dumps({
        'command': cmd.upper(),
        'args': args or {}
    })


def make_res(res):
    # type: (object) -> str
    # Throw whatever the result is in a JSON response
    return json.dumps({'res': res})


def parse_res(res):
    # type: (str) -> object
    # Read the result from a JSON response
    return json.loads(res)['res']


class VoteGenerator:
    """
    Vote format:
    Assume for example we have 3 candidates, and 100 voters
    We need to know the number of bits needed to represent a vote:
        100 voters -> 7 bits per candidate (block_size)
        Every vote is (1 + (# candidates)*block_size) bits -> 22 bits

    Then, the possible votes here look like this:
        |     |  C1  |  C2  |  C3   |
    ----+---------------------------+
    V1  |    1000000100000000000000 |
    V2  |    1000000000000010000000 |
    V3  |    1000000000000000000001 |
    ----+---------------------------+
    sum | ...1000000100000010000001 |
    ----+---------------------------+
    This is how votes will be stored, and these entire rows can be added
    to get the totals

    Once we have totals, we translate to votes for each candidate:
    - Discard most significant bits after (# candidates)*block_size
        11000000100000010000001
                |
                v
          000000100000010000001

    - Split on block_size
        000000100000010000001
                |
                v
        0000001 0000001 0000001

    - These individual numbers are the results for each candidate
    """

    def __init__(self, num_candidates):
        self.num_cands = num_candidates
        self.block_size = None

    def gen(self, cindex):
        """ Generates a vote for the given candidate index

        The index will follow the format:
             0       1       2    ...
        1 0000001 0000000 0000000 ...

        Args:
            cindex (int): index of the candidate to vote for

        Returns:
            long: Generated vote for the candidate
        """
        if self.block_size is None:
            raise ValueError('Block size is not set')

        vote_len = self.block_size * self.num_cands
        vote = (1 << vote_len) | (1 << ((self.num_cands - cindex - 1) * self.block_size))
        return vote

    def parse(self, vote):
        """ Parses a packed vote to get the results for every candidate

        Example:
            3 candidates, block_size=5

            To separate the results, we take the following steps:
                1. 110000010001100010 <-- example sum
                2.   0000010001100010
                3. 000001 00011 00010
                4.      1     3     2
        Args:
            vote (long): Packed vote to unpack

        Returns:
            list: List of the results for every candidate
        """
        if self.block_size is None:
            raise ValueError('Block size is not set')

        # Mask to get one vote at a time
        vote_mask = (1 << self.block_size) - 1
        return [(vote >> (self.block_size * i)) & vote_mask for i in xrange(self.num_cands)][::-1]
