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


        self.cand = IntVar()

        #2.5: Add candidate buttons
        for cnum,cand in enumerate(voter.candidates):
            Radiobutton(self.master, text=cand, variable=self.cand, value=cnum).grid(row=cnum+1, column=0)

        #3: Create the widget using a master as parent
        self.mainwindow = builder.get_object('Frame_1', self.master)
        
        #Connect buttons to functions
        builder.connect_callbacks(self)
 
    #Update output label
    def updateout(self, data):
        try: 
            voter.check_logged_in()
            self.builder.get_object('LoggedinLabel')["text"] = "Logged In As: " + voter.login_user
        except:
            self.builder.get_object('LoggedinLabel')["text"] = 'Not Logged In'
        self.builder.get_object('OutputLabel')["text"] = data

    #Get value of element by name
    def getel(self, name):
        return self.builder.get_object(name).get()

    #Callback for register button
    def registerclick(self):
        self.updateout(voter.register_voter(True, self.getel('UsernameBox'), self.getel('PasswordBox')))
    
    #Callback for vote button
    def voteclick(self):
        try:
            voter.check_logged_in()
            self.updateout(voter.cast_vote(True, self.cand.get()))
        except:
            self.updateout('Not Logged In')

    #Callback for login button
    def loginclick(self):
       self.updateout(voter.login_voter(True, self.getel('UsernameBox'), self.getel('PasswordBox')))
 
    #Callback for logout button
    def logoutclick(self):
        try:
            self.updateout(voter.logout_voter(True))
        except:
            self.updateout('Not Logged In')

    #Callback for exit button
    def exitclick(self):
        self.updateout(voter.close_and_quit(True))


#Build and start application
root = tk.Tk()
app = Application(root)
app.run()

