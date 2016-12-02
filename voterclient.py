#!/usr/bin/env python2
import hashlib
import Tkinter as tk
from Tkinter import *
import pygubu
import tkMessageBox as messagebox
import voter
from common import *


class Application(pygubu.TkApplication):
    def _create_ui(self):
        #1: Create a builder
        self.builder = builder = pygubu.Builder()
        #2: Load ui file
        builder.add_from_file('client.ui')
        #3: Create the widget using a master as parent
        
        self.cand = IntVar()

        for cnum,cand in enumerate(voter.candidates):
            Radiobutton(self.master, text=cand, variable=self.cand, value=cnum).grid(row=cnum+1, column=0)

        self.mainwindow = builder.get_object('Frame_1', self.master)
        builder.connect_callbacks(self)
    
    def getel(self, name):
        return self.builder.get_object(name).get()

    def registerclick(self):
        voter.register_voter(True, self.getel('UsernameBox'), self.getel('PasswordBox'))

    def voteclick(self):
        voter.cast_vote(True, self.cand.get())

    def loginclick(self):
        voter.login_voter(True, self.getel('UsernameBox'), self.getel('PasswordBox'))

    def logoutclick(self):
        voter.close_and_quit(True)


root = tk.Tk()
app = Application(root)
app.run()

