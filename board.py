#!/usr/bin/env python2

import thread
from SocketServer import ThreadingTCPServer

from Crypto.Util.number import getRandomRange

import paillier
from common import *

import json

# Paillier keys
pub = None  # type: paillier.PublicKey
priv = None  # type: paillier.PrivateKey

# Candidates running in the election
candidates = ['dat boi', 'Shirls', 'RIPSEC']

# Table containing vote results
board = {}

# Connect to the registrar
reg_sock = SecureSocket(socket.AF_INET, socket.SOCK_STREAM)
reg_sock.connect((HOST, PORT_REGISTRAR))

# Get its key
reg_sock.send(make_cmd('KEY'))
reg_pub = parse_res(reg_sock.recvline())
reg_pub = RSA.construct((long(reg_pub['n']), long(reg_pub['e'])))


class BoardHandler(SecureCommandHandler):
    reg_open = False
    votegen = VoteGenerator(len(candidates))

    def init_commands(self):
        self.add_cmd('regopen', lambda _: self.reg_open)  # Is registration currently allowed?
        self.add_cmd('key', lambda _: pub.n)  # Get the public key (modulus)
        self.add_cmd('candidates', lambda _: candidates)  # Get list of candidates
        self.add_cmd('vote', self.attempt_vote)

    def validate_signature(self, vote, signed):
        return vote == pow(signed, reg_pub.e, reg_pub.n)

    def validate_voter(self, name, password):
        reg_sock.send(make_cmd('user', {'name': name, 'password': password}))
        return parse_res(reg_sock.recvline())  # TODO: assuming this is a bool, change if needed

    def validate_zkp_knowledge(self, vote, know_A=1000):
        # receive u
        know_u = long(input()) % vote.pub.n_sq
        # 3 rounds, A = 1000, p_valid = 1/(1000^3)
        # self.println
        know_e = getRandomRange(0, know_A)
        # send e
        self.println(know_e)
        know_vw = input()
        know_v, know_w = know_vw.strip().split(',')
        test = (vote.pub.g ** know_v * vote.ctxt ** know_e * know_w ** vote.pub.N) % vote.pub.n_sq

        if know_u == test:
            self.println("PASS")
            return True

        self.println("FAIL")
        return False

    def validate_zkp_in_set(self, vote, A = 1000):
        vote_set = map(self.votegen.gen, xrange(self.votegen.num_cands))
        u_raw = input()
        u = json.loads(u)

        e = getRandomRange(0, A)
        self.println(e)

        ev = input()
        ev_dict = json.loads(ev)

        es = ev_dict["e"]
        vs = ev_dict["v"]

        for j in xrange(self.votegen.num_cands):
            if (vs[j]**vote.pub.n) % vote.pub.n_sq != (u[j]*(vote.ctxt*inverse(vote.pub.g**voter_set[j], vote.pub.n_sq))**es[j]) % vote.pub.n_sq:
                self.println("FAIL")
                return False

        self.println("PASS")
        return True


    def attempt_vote(self, args):
        if self.reg_open:
            # Not allowed to vote yet
            return 'The election is not currently running'

        try:
            name = args['name']
            password = args['password']
            vote = args['vote']
            sig = args['signature']
        except KeyError:
            return 'VOTE usage: [name] [password] [vote] [signature]'

        if self.validate_voter(name, password) \
                and self.validate_signature(vote, sig) \
                and self.validate_zkp_knowledge(vote) \
                and self.validate_zkp_in_set(vote):

            # Add the voter to the table if we haven't yet
            voterkey = '{}:{}'.format(name, password)  # TODO: probably change how we keep track of this
            if voterkey in board:
                # A vote has already been cast by this voter
                return 'Vote not accepted'

            # All checks passed
            board[voterkey] = vote
            return 'Vote accepted!'
        return 'Vote not accepted'


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

    reg_sock.send(make_cmd('count'))
    BoardHandler.votegen.block_size = parse_res(reg_sock.recvline())
    BoardHandler.reg_open = False
    raw_input('--- BEGIN VOTING PHASE ---')

    print '--- VOTING COMPLETE, COUNTING VOTES ---'
    results = zip(candidates, BoardHandler.votegen.parse(priv.decrypt(sum(board.values()))))

    print 'RESULTS\n------------'
    for cand, result in results:
        print '{}: {}'.format(cand, result)

    reg_sock.send(make_cmd('quit'))
    reg_sock.close()
