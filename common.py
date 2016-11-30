"""
Common variables/utilities shared between services
"""
import json
from SocketServer import StreamRequestHandler

HOST = 'localhost'
PORT_REGISTRAR = 9001
PORT_BOARD = 9002


class CommandHandler(StreamRequestHandler):
    def __init__(self, request, client_address, server):
        self.commands = {}
        self.init_commands()
        StreamRequestHandler.__init__(self, request, client_address, server)

    def init_commands(self):
        raise NotImplementedError('Define commands for this handler')

    def println(self, s=''):
        self.wfile.write('{}\n'.format(s))

    def input(self, prompt=''):
        self.wfile.write(prompt)
        return self.rfile.readline().rstrip('\r\n')

    def handle(self):
        try:
            cmd = json.loads(self.rfile.readline())
            assert 'command' in cmd and 'args' in cmd
            res = self.commands[cmd['command']](cmd['args'])
            self.println(json.dumps({'res': res}))
        except:
            self.println('Invalid input')


def make_cmd(cmd, args=None):
    return json.dumps({
        'command': cmd.lower(),
        'args': args or {}
    })
