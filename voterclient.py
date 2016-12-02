#!/usr/bin/env python2
import hashlib
import Tkinter as tk
import pygubu
import tkMessageBox as messagebox

from common import *

#connect to server
s = RSASocket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT_REGISTRAR))

#valid commands with # of args
commands = {'REGISTER' : 3, 'SIGN' : 4, 'KEY' : 1, 'USER' : 2}


class Application(pygubu.TkApplication):
    def _create_ui(self):
        #1: Create a builder
        self.builder = builder = pygubu.Builder()
        #2: Load ui file
        builder.add_from_file('client.ui')
        #3: Create the widget using a master as parent
        self.mainwindow = builder.get_object('Frame_1', self.master)
        builder.connect_callbacks(self)
    
    def getel(self, name):
        return self.builder.get_object(name).get()

    def registerclick(self):
        s.send(make_cmd('REGISTER', {'name': self.getel('UsernameBox'), 'password': hashlib.sha256(self.getel('PasswordBox')).hexdigest()}))
        messagebox.showinfo('Message', parse_res(s.recvline().strip()))

    def signclick(self):
        s.send(make_cmd('SIGN', {'name': self.getel('UsernameBox'), 'password': hashlib.sha256(self.getel('PasswordBox')).hexdigest(), 'vote': int(self.getel('SignBox'))}))
        messagebox.showinfo('Message', parse_res(s.recvline().strip()))

    def keyclick(self):
        s.send(make_cmd('KEY'))
        key = parse_res(s.recvline().strip())
        messagebox.showinfo('Message', "(" + str(key['e']) + ', ' + str(key['n']) + ')')


root = tk.Tk()
app = Application(root)
app.run()

