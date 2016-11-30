import SocketServer, hashlib, sqlite3, threading

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


    def handle(self):
        self.voterdb = sqlite3.connect("voters.db")
        self.cursor = self.voterdb.cursor()
    
        self.data = self.rfile.readline().strip()
        
        if "REGISTER " in self.data:
            info = self.data.split(' ')
            try:
                self.wfile.write(self.register(info[1], info[2]))
            except:
                self.wfile.write("REGISTER [username] [password]")
        
        else:
            self.wfile.write("Options: REGISTER")


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

HOST, PORT = "localhost", 1337

SocketServer.TCPServer.allow_reuse_address = True
server = ThreadedTCPServer((HOST, PORT), VoterHandler)

server.serve_forever()

