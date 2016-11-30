import SocketServer, hashlib, sqlite3, threading
from Crypto.PublicKey import RSA
from ast import literal_eval
import base64

def genKey(nbits=2048):
    return RSA.generate(nbits)

key = genKey(2048)

voterdb = sqlite3.connect("voters.db")
cursor = voterdb.cursor()

try:
    cursor.execute("create table voters (name text, password text)")
    voterdb.commit()
except:
    pass

voterdb.close()

class VoterHandler(SocketServer.StreamRequestHandler):
    
    def sql(self, query, args=None):
        if args:
            return self.cursor.execute(query, args)
        else:
            return self.cursor.execute(query)

    def salt(self, password):
        return 'whyso' + password + 'salty'

    def register(self, name, password):
        
        if self.sql("select name from voters where name=?",(name,)).fetchone() != None:
            return "Name already registered\n"
        
        voterinfo = (name, hashlib.sha256(self.salt(password)).hexdigest())
        print voterinfo
        self.sql("insert into voters values (?,?)", voterinfo)
        self.voterdb.commit()

        for row in self.sql("select name,password from voters where 1=1"):
            print row

        return "Successfully registered"

    def send(self, data):
        self.wfile.write(data)

    def handle(self):
        self.voterdb = sqlite3.connect("voters.db")
        self.cursor = self.voterdb.cursor()
        
        self.send(str(key.e) + ',' + str(key.n))
        while True:
            self.data = base64.b64decode(self.rfile.readline().strip())
            dec = key.decrypt(self.data).strip()
            args = dec.split(' ')
            command = args[0]

            if command == "REGISTER":
                try:
                    self.send(self.register(args[1], args[2]))
                except:
                    self.send("REGISTER [username] [password]")
            
            elif command == "KEY":
                self.send(str(key.e) + ',' + str(key.n))

            elif command == "QUIT":
                break

            else:
                self.send("Options: REGISTER, KEY, QUIT")

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

HOST, PORT = "localhost", 1337

SocketServer.TCPServer.allow_reuse_address = True
server = ThreadedTCPServer((HOST, PORT), VoterHandler)

server.serve_forever()
