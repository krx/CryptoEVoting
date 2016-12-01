import hashlib
import sqlite3
from SocketServer import ThreadingTCPServer

from common import *

reg_key = RSA.generate(2048)

voterdb = sqlite3.connect("voters.db")
cursor = voterdb.cursor()

try:
    cursor.execute("CREATE TABLE voters (name TEXT, password TEXT)")
    voterdb.commit()
except:
    pass

voterdb.close()


class VoterHandler(RSACommandHandler):
    def init_commands(self):
        self.add_cmd('REGISTER', self.register)
        self.add_cmd('SIGN', self.sign)
        self.add_cmd('KEY', lambda _: {'e': reg_key.e, 'n': reg_key.n})
        self.add_cmd('USER', self.userexists)

    def sql(self, query, args=None):
        if args:
            return self.cursor.execute(query, args)
        else:
            return self.cursor.execute(query)

    def salt(self, password):
        return 'whyso' + password + 'salty'

    def register(self, args):
        name = None
        password = None
        try:
            name = args['name']
            password = args['password']
        except KeyError:
            return 'REGISTER [name] [password]'

        voterinfo = (name, hashlib.sha256(self.salt(password)).hexdigest())  # hash(salt(pass))
        if self.userexists({'name': name, 'password': voterinfo[1]}):
            return "Name already registered"

        self.sql("insert into voters values (?,?)", voterinfo)
        self.voterdb.commit()

        for row in self.sql("select name,password from voters where 1=1"):
            print row

        return "Successfully registered"

    def sign(self, args):
        try:
            name = args['name']
            password = args['password']
            vote = args['vote']
        except KeyError:
            return 'SIGN [name] [password] [vote]'

        password = hashlib.sha256(self.salt(password)).hexdigest()
        if self.sql("select name from voters where name=? and password=?", (name, password,)).fetchone() is not None:
            return str(pow(vote, reg_key.d, reg_key.n))
        else:
            return "Incorrect Login Details"

    def userexists(self, args):
        try:
            name = args['name']
            password = args['password']
        except KeyError:
            return 'USER [name] [password]'

        if self.sql("select name from voters where name=? and password=?", (name, password,)).fetchone() is not None:
            return True
        return False

    def setup(self):
        RSACommandHandler.setup(self)
        self.voterdb = sqlite3.connect("voters.db")
        self.cursor = self.voterdb.cursor()


ThreadingTCPServer.allow_reuse_address = True
server = ThreadingTCPServer((HOST, PORT_REGISTRAR), VoterHandler)

server.serve_forever()
