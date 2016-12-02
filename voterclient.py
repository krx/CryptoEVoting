#!/usr/bin/env python2
import hashlib
import Tkinter as tk
from Tkinter import *
import pygubu
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
 
    def updateout(self, data):
        try: 
            voter.check_logged_in()
            self.builder.get_object('LoggedinLabel')["text"] = "Logged In As: " + voter.login_user
        except:
            self.builder.get_object('LoggedinLabel')["text"] = 'Not Logged In'
        self.builder.get_object('OutputLabel')["text"] = data

    def getel(self, name):
        return self.builder.get_object(name).get()

    def registerclick(self):
        self.updateout(voter.register_voter(True, self.getel('UsernameBox'), self.getel('PasswordBox')))

    def voteclick(self):
        self.updateout(voter.cast_vote(True, self.cand.get()))

    def loginclick(self):
       self.updateout( voter.login_voter(True, self.getel('UsernameBox'), self.getel('PasswordBox')))
 
    def logoutclick(self):
        try:
            self.updateout(voter.logout_voter(True))
        except:
            self.updateout('Not Logged In')
    def exitclick(self):
        self.updateout(voter.close_and_quit(True))


root = tk.Tk()
app = Application(root)
app.run()

