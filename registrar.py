import SocketServer, hashlib, sqlite3, threading, base64, json
from Crypto.PublicKey import RSA

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
        
        voterinfo = (name, hashlib.sha256(self.salt(password)).hexdigest()) #hash(salt(pass))
        print voterinfo
        self.sql("insert into voters values (?,?)", voterinfo)
        self.voterdb.commit()

        for row in self.sql("select name,password from voters where 1=1"):
            print row

        return "Successfully registered"

    def sign(self, name, password, vote):
        password = hashlib.sha256(self.salt(password)).hexdigest()
        if self.sql("select name from voters where name=? and password=?",(name,password,)).fetchone() != None:
            return str(pow(int(vote), key.d, key.n))
        else:
            return "Incorrect Login Details"

    def send(self, data):
        self.wfile.write(data)

    def handle(self):
        self.voterdb = sqlite3.connect("voters.db")
        self.cursor = self.voterdb.cursor()
        
        self.send(str(key.e) + ',' + str(key.n))
        while True:
            self.data = base64.b64decode(self.rfile.readline().strip())
            dec = key.decrypt(self.data).strip()
            jstr = json.loads(dec)
            print jstr
            command = jstr['command']


            if command == "REGISTER":
                try:
                    self.send(self.register(jstr['name'], jstr['password']))
                except:
                    self.send("REGISTER [name] [password]")
            
            elif command == "KEY":
                self.send(str(key.e) + ',' + str(key.n))

            elif command == "QUIT":
                break
            
            elif command == "SIGN":
                #try:
                print "sign"
                self.send(self.sign(jstr['name'], jstr['password'], jstr['vote']))
                #except:
                #    self.send("SIGN [name] [password] [vote]")

            else:
                self.send("Options: KEY, QUIT, REGISTER, SIGN")

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

HOST, PORT = "localhost", 1337

SocketServer.TCPServer.allow_reuse_address = True
server = ThreadedTCPServer((HOST, PORT), VoterHandler)

server.serve_forever()
