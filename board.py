#!/usr/bin/env python2

import thread
from SocketServer import ThreadingTCPServer

import paillier
from common import *

# Paillier keys
pub = None  # type: paillier.PublicKey
priv = None  # type: paillier.PrivateKey

# Table containing vote results
board = {}


# class Board:
#     def __init__(self):
#         pass
#
#     # Is the sum of the votes 1
#     def validateRowTotal(self):
#         pass
#
#     # Is the vote in the set {0, 1}?
#     # Has the vote been tampered with?
#     # Using ZKP
#     def validateVote(self):
#         pass
#
#     def addVoteToTable(self):
#         pass


class BoardHandler(RSACommandHandler):
    reg_open = False

    def init_commands(self):
        # Is registration currently allowed?
        self.add_cmd('regopen', lambda _: self.reg_open)

        # Get the public key (modulus)
        self.add_cmd('pubkey', lambda _: pub.n)

        self.add_cmd('vote', self.attempt_vote)

    def attempt_vote(self, args):
        if self.reg_open:
            # Not allowed to vote yet
            return

        print args


if __name__ == "__main__":
    # Generate a new set of keys
    print 'Generating Paillier key pair ...',
    pub, priv = paillier.gen_keypair()
    print 'done!'

    print 'Starting board server at {}:{}'.format(HOST, PORT_BOARD)
    ThreadingTCPServer.allow_reuse_address = True
    srv = ThreadingTCPServer((HOST, PORT_BOARD), BoardHandler)
    thread.start_new_thread(srv.serve_forever, ())

    # There are two "phases" before shutting down
    BoardHandler.reg_open = True
    raw_input('--- BEGIN REGISTRATION PHASE ---')

    BoardHandler.reg_open = False
    raw_input('--- BEGIN VOTING PHASE ---')

    print '--- VOTING COMPLETE, COUNTING VOTES ---'
    # do counting stuff here
