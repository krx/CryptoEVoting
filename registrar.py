import hashlib
import sqlite3
from SocketServer import ThreadingTCPServer

from common import *

#generate registration key
reg_key = RSA.generate(2048)

#initial connection to db, just to ensure voter table exists
voterdb = sqlite3.connect("voters.db")
cursor = voterdb.cursor()


#Create table if it does not exist
try:
    cursor.execute("CREATE TABLE voters (name TEXT, password TEXT)")
    voterdb.commit()
except:
    pass

voterdb.close()

#Instance per voter
class VoterHandler(RSACommandHandler):
    
    #register all accepted commands
    def init_commands(self):
        self.add_cmd('REGISTER', self.register)
        self.add_cmd('SIGN', self.sign)
        self.add_cmd('KEY', lambda _: {'e': reg_key.e, 'n': reg_key.n})
        self.add_cmd('USER', self.userexists)
        self.add_cmd('COUNT', self.user_count)

    #perform sql query (with prepared statements (it pains me to do this))
    def sql(self, query, args=None):
        if args:
            return self.cursor.execute(query, args)
        else:
            return self.cursor.execute(query)

    #tries to add voter to table if not already in it
    def register(self, args):
        name = None
        password = None
        try:
            name = args['name']
            password = args['password']
        except KeyError:
            return 'REGISTER [name] [password]'
        
        
        #makes sure voter isn't registered already
        if self.userexists(args):
            return "Name already registered"

        #calculates what would be stored in the table
        voterinfo = (name, password) # pass hashed+salted in common.py
        
        #adds voter to table
        self.sql("insert into voters values (?,?)", voterinfo)
        self.voterdb.commit()

        #debug print message, prints new table contents
        for row in self.sql("select name,password from voters where 1=1"):
            print row

        return "Successfully registered"

    #Attempts to sign encrypted vote
    def sign(self, args):
        try:
            name = args['name']
            password = args['password']
            vote = args['vote']
        except KeyError:
            return 'SIGN [name] [password] [vote]'

        #checks if user exists in table
        if self.sql("select name from voters where name=? and password=?", (name, password,)).fetchone() is not None:
            #return signature of vote
            return str(pow(vote, reg_key.d, reg_key.n))
        else:
            return "Incorrect Login Details"

    #ulility function for checking if voter (name,password) exists in the table
    def userexists(self, args):
        try:
            name = args['name']
            password = args['password']
        except KeyError:
            return 'USER [name] [password]'
        if self.sql("select name from voters where name=? and password=?", (name, password,)).fetchone() is not None:
            return True
        return False
    
    #returns number of voters in table
    def user_count(self, args):
        return self.sql("select count(*) from voters").fetchone()[0]

    #init method, sets up db connection and RSACommandHandler
    def setup(self):
        RSACommandHandler.setup(self)
        self.voterdb = sqlite3.connect("voters.db")
        self.cursor = self.voterdb.cursor()

#bc networking
ThreadingTCPServer.allow_reuse_address = True
server = ThreadingTCPServer((HOST, PORT_REGISTRAR), VoterHandler)

#start that shizz
server.serve_forever()
