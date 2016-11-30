import SocketServer, hashlib, sqlite3

voterdb = sqlite3.connect("voters.db")
cursor = voterdb.cursor()
try:
    cursor.execute("create table voters (name text, password text)")

    voterdb.commit()
except:
    pass


class VoterHandler(SocketServer.StreamRequestHandler):

    def salt(self, password):
        return 'whyso' + password + 'salty'

    def register(self, name, password):
        
        if cursor.execute("select name from voters where name=?",(name,)).fetchone() != None:
            return "Name already registered\n"
        
        voterinfo = (name, hashlib.sha256(self.salt(password)).hexdigest())
        cursor.execute("insert into voters values (?,?)", voterinfo)
        voterdb.commit()

        #for row in cursor.execute("select name,password from voters where 1=1"):
        #    print row

        return "Successfully registered"


    def handle(self):
        
        self.data = self.rfile.readline().strip()
        
        if "REGISTER " in self.data:
            info = self.data.split(' ')
            self.wfile.write(self.register(info[1], info[2]))
        
        else:
            self.wfile.write("not implemented yet")



HOST, PORT = "localhost", 1337

# Create the server, binding to localhost on port 9999

SocketServer.TCPServer.allow_reuse_address = True
server = SocketServer.TCPServer((HOST, PORT), VoterHandler)

# Activate the server; this will keep running until you
# interrupt the program with Ctrl-C
server.serve_forever()
