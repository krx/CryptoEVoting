#!/usr/bin/env python2

import thread
from SocketServer import ThreadingTCPServer

import paillier
from common import *

# Paillier keys
pub = None  # type: paillier.PublicKey
priv = None  # type: paillier.PrivateKey

# Candidates running in the election
candidates = ['dat boi', 'Shirls', 'RIPSEC']

# Table containing vote results
board = {}

# Connect to the registrar
reg_sock = RSASocket(socket.AF_INET, socket.SOCK_STREAM)
reg_sock.connect((HOST, PORT_REGISTRAR))

# Get its key
reg_sock.send(make_cmd('KEY'))
reg_pub = parse_res(reg_sock.recvline())
reg_pub = RSA.construct((long(reg_pub['n']), long(reg_pub['e'])))


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

    def validate_signature(self, vote, signed):
        return vote == pow(signed, reg_pub.e, reg_pub.n)

    def validate_voter(self, name, password):
        reg_sock.send(make_cmd('user', {'name': name, 'password': password}))
        res = parse_res(reg_sock.recvline())
        # ???

    def validate_candidate(self, candidat):
        pass

    def validate_zkp_knowledge(self, vote):
        pass

    def validate_zkp_in_set(self, vote):
        pass

    def attempt_vote(self, args):
        if self.reg_open:
            # Not allowed to vote yet
            return 'The election is not currently running'

        try:
            name = args['name']
            password = args['password']
            candidate = args['candidate']
            vote = args['vote']
            sig = args['signature']
        except KeyError:
            return 'VOTE usage: [name] [password] [candidate] [vote] [signature]'

        if self.validate_voter(name, password) \
                and self.validate_signature(vote, sig) \
                and self.validate_candidate(candidate) \
                and self.validate_zkp_knowledge(vote) \
                and self.validate_zkp_in_set(vote):

            # Add the voter to the table if we haven't yet
            voterkey = '{}:{}'.format(name, password)  # TODO: probably change how we keep track of this
            if voterkey not in board:
                board[voterkey] = {}

            if candidate in board[voterkey]:
                # A vote has already been cast for this candidate
                return 'Vote not accepted'

            # All checks passed
            board[voterkey][candidate] = vote
            return 'Vote accepted!'
        return 'Vote not accepted'


def count_votes(cand):
    votes = [board[voter][cand] for voter in board.keys() if cand in board[voter]]
    result = priv.decrypt(sum(votes))
    return cand, len(votes), result


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
    results = map(count_votes, candidates)

    print 'RESULTS\n------------'
    total_votes = 0
    total_results = 0
    for cand, num_votes, result in results:
        total_votes += num_votes
        total_votes += result
        print '{}: {}'.format(cand, result)
    print '------------\nTotal votes cast: {}'.format(total_votes)

    if total_votes != total_results:
        print 'SOMETHING WENT WRONG'
        print 'THE ELECTION WAS RIGGED'
