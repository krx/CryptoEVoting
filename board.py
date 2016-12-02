#!/usr/bin/env python2

import json
import thread
from SocketServer import ThreadingTCPServer
from hashlib import sha256

from Crypto.Util.number import getRandomRange, inverse

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
        vote_hash = int(sha256(str(vote)).hexdigest(), 16)
        return vote_hash == pow(signed, reg_pub.e, reg_pub.n)

    def validate_voter(self, name, password):
        reg_sock.send(make_cmd('user', {'name': name, 'password': password}))
        return parse_res(reg_sock.recvline())  # TODO: assuming this is a bool, change if needed

    def validate_zkp_knowledge(self, vote, know_A=1000):
        # receive u
        know_u = long(self.input()) % pub.n_sq
        # print 'GOT DAT U'
        # 3 rounds, A = 1000, p_valid = 1/(1000^3)
        # self.println
        know_e = getRandomRange(0, know_A)
        # send e
        self.println(know_e)
        # print 'SENT DAT E'
        know_vw = self.input()
        # print 'GOT DAT VW'
        know_v, know_w = map(long, know_vw.strip().split(','))
        test = (pow(pub.g, know_v, pub.n_sq) * pow(vote, know_e, pub.n_sq) * pow(know_w, pub.n, pub.n_sq)) % pub.n_sq

        if know_u == test:
            self.println("PASS")
            return True

        self.println("FAIL")
        return False

    def validate_zkp_in_set(self, vote, A=1000):
        vote_set = map(self.votegen.gen, xrange(self.votegen.num_cands))
        u_raw = self.input()
        u = json.loads(u_raw)

        e = getRandomRange(0, A)
        self.println(e)

        ev = self.input()
        ev_dict = json.loads(ev)

        es = ev_dict["e"]
        vs = ev_dict["v"]

        for j in xrange(self.votegen.num_cands):
            # print 'j -', j
            if pow(vs[j], pub.n, pub.n_sq) != (u[j] * pow(vote * inverse(pow(pub.g, vote_set[j], pub.n_sq), pub.n_sq), es[j], pub.n_sq)) % pub.n_sq:
                # print 'FAIL'
                self.println("FAIL")
                return False
        # print 'PASS'
        self.println("PASS")
        return True

    def attempt_vote(self, args):
        if self.reg_open:
            # Not allowed to vote yet
            return 'The election is not currently running'

        try:
            name = args['name']
            password = args['passhash']
            vote = args['vote']
            sig = args['signature']
        except KeyError:
            return 'VOTE usage: [name] [password] [vote] [signature]'

        # if self.validate_voter(name, password) \
        #         and self.validate_signature(vote, sig) \
        #         and self.validate_zkp_knowledge(vote) \
        #         and self.validate_zkp_in_set(vote):
        voterkey = '{}:{}'.format(name, password)  # TODO: probably change how we keep track of this
        if voterkey in board:
            # A vote has already been cast by this voter
            return 'Vote not accepted'

        if not self.validate_voter(name, password):
            return 'Vote not accepted USER'
        # print 'USER DONE'
        if not self.validate_signature(vote, sig):
            return 'Vote not accepted SIG'
        # print 'SIG DONE'
        for attempt in xrange(5):
            # print attempt
            if not self.validate_zkp_knowledge(vote):
                return 'Vote not accepted ZKP K'
        # print 'ZKPK DONE'
        for attempt in xrange(5):
            # print attempt
            if not self.validate_zkp_in_set(vote):
                return 'Vote not accepted ZKP V'

        # All checks passed
        board[voterkey] = paillier.EncryptedMessage(pub, vote)
        return 'Vote accepted!'
        # return 'Vote not accepted'


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
    BoardHandler.votegen.block_size = parse_res(reg_sock.recvline()).bit_length()
    BoardHandler.reg_open = False
    raw_input('--- BEGIN VOTING PHASE ---')

    print '--- VOTING COMPLETE, COUNTING VOTES ---'
    if len(board.values()) == 0:
        print 'Nobody voted, RIP'
    else:
        results = zip(candidates, BoardHandler.votegen.parse(priv.decrypt(sum(board.values()))))

        print 'RESULTS\n------------'
        for cand, result in results:
            print '{}: {}'.format(cand, result)

    srv.shutdown()

    # Disconnect from registrar
    reg_sock.send(make_cmd('quit'))
    reg_sock.close()
