#!/usr/bin/env python2

from hashlib import sha256

from Crypto.Util.number import getRandomRange, GCD, inverse
import json

import paillier
from paillier import random_range_coprime
from common import *

# Connect to registrar
reg = SecureSocket()
reg.connect((HOST, PORT_REGISTRAR))

# Get the registrar's public key
reg.send(make_cmd('key'))
reg_key = parse_res(reg.recvline())
reg_key = RSA.construct((long(reg_key['n']), long(reg_key['e'])))

# Connect to board
board = SecureSocket()
board.connect((HOST, PORT_BOARD))

# Get the board's public key
board.send(make_cmd('key'))
board_key = paillier.PublicKey(parse_res(board.recvline()))

# Get the list of candidates
board.send(make_cmd('candidates'))
candidates = parse_res(board.recvline())
candidate_menu = '\n'.join(['{}) {}'.format(i + 1, cand) for i, cand in enumerate(candidates)])

# Will be used to create votes
votegen = VoteGenerator(len(candidates))

# Keep track of the current user
login_user = login_pass = None


class LoginError(Exception): pass
class SignError(Exception): pass


def check_logged_in():
    # These are only ever set once the registrar is okay with it
    if login_user is None or login_pass is None:
        raise LoginError()


def register_voter(gui=False, user=None, password=None):
    global login_user, login_pass
    # Can't register if already logged in
    try:
        check_logged_in()
        return 'Already Logged In'
    except:
        pass

    # We can only register in the registration phase
    board.send(make_cmd('regopen'))
    if not parse_res(board.recvline()):
        return 'Registration is currently closed'

    # Attempt to register this voter
    if not gui:
        reg.send(make_cmd('register', {
            'name': raw_input('Enter name: '),
            'password': sha256(raw_input('Enter password: ')).hexdigest()
        }))
    else:
        reg.send(make_cmd('register', {
            'name': user,
            'password': sha256(password).hexdigest()
        }))
    return parse_res(reg.recvline())


def login_voter(gui=False, user=None, password=None):
    global login_user, login_pass

    try:
        check_logged_in()
        return "Already Logged In"
    except:
        pass
    # Attempt to login as this voter
    args = None

    if not gui:
        args = {
            'name': raw_input('Enter name: '),
            'password': sha256(raw_input('Enter password: ')).hexdigest()
        }
    else:
        args = {
            'name': user,
            'password': sha256(password).hexdigest()
        }
    reg.send(make_cmd('user', args))

    # Save info if successful
    if parse_res(reg.recvline()):
        login_user = args['name']
        login_pass = args['password']
        return 'Successfully logged in as \'' + args['name'] + '\''
    else:
        return 'Could not login'


def logout_voter(gui=False):
    check_logged_in()
    global login_user, login_pass
    login_user = login_pass = None
    return 'Logged out'


def sign_vote(vote):
    # type: (paillier.EncryptedMessage) -> long
    check_logged_in()

    # Blind and send our encrypted vote
    # The hash is our m
    vote_hash = int(sha256(str(vote.ctxt)).hexdigest(), 16)

    # Pick r, calculate (mr^e mod n) and send it to get signed
    blind_r = getRandomRange(2, reg_key.n)
    blinded_vote = (vote_hash * pow(blind_r, reg_key.e, reg_key.n)) % reg_key.n
    reg.send(make_cmd('sign', {
        'name': login_user,
        'password': login_pass,
        'vote': blinded_vote
    }))

    # Get the signed vote and undo the blinding
    try:
        # Unblind the signature to get our result
        signed = (parse_res(reg.recvline()) * inverse(blind_r, reg_key.n)) % reg_key.n
        assert pow(signed, reg_key.e, reg_key.n) == vote_hash
        return signed
    except (ValueError, AssertionError):
        raise SignError()

# adapted from Practical Multi-Candidate Election System by Baudron
# corresponds to validate_zkp_knowledge board.py
# Prove that client knows plaintext
def zkp_prove_knowledge(evote, pvote):
    # type: (paillier.EncryptedMessage, long) -> bool
    # choose r in Zn
    know_r = getRandomRange(0, evote.pub.n)
    # choose s in Zn star
    know_s = random_range_coprime(0, evote.pub.n, evote.pub.n)
    # calc u
    know_u = (pow(evote.pub.g, know_r, evote.pub.n_sq) * pow(know_s, evote.pub.n, evote.pub.n_sq)) % evote.pub.n_sq
    # send u
    board.send(str(know_u))

    # receive e
    know_e = long(board.recvline().strip())

    # calc v, w
    know_v = (know_r - know_e * pvote) % evote.pub.n
    know_w = (know_s * pow(inverse(evote.rand_num, evote.pub.n), know_e, evote.pub.n)) % evote.pub.n

    board.send(str(know_v) + "," + str(know_w))

    result = board.recvline().strip()
    return result == 'PASS'

# from Practical Multi-Candidate Election System by Baudron
# corresponds to validate_zkp_in_set in board.py
# Prove message is valid vote
def zkp_prove_valid(evote, pvote):
    # type: (paillier.EncryptedMessage, long) -> bool
    vote_set = map(votegen.gen, xrange(votegen.num_cands))
    vote_i = vote_set.index(pvote)
    ro = random_range_coprime(0, evote.pub.n, evote.pub.n)
    vote_es = []
    vote_vs = []
    vote_us = []
    for j in xrange(votegen.num_cands):
        if j == vote_i:
            vote_es.append(0)
            vote_vs.append(0)
            vote_us.append(pow(ro, evote.pub.n, evote.pub.n_sq))
            continue

        e_j = getRandomRange(0, evote.pub.n)
        vote_es.append(e_j)

        v_j = random_range_coprime(0, evote.pub.n, evote.pub.n)
        vote_vs.append(v_j)

        u_j = (pow(v_j, evote.pub.n, evote.pub.n_sq) * pow(pow(evote.pub.g, vote_set[j], evote.pub.n_sq) * inverse(evote.ctxt, evote.pub.n_sq), e_j, evote.pub.n_sq)) % evote.pub.n_sq
        vote_us.append(u_j)

    # send u's
    board.send(json.dumps(vote_us))

    # receive e
    chal_e = int(board.recvline().strip())

    e_i = (chal_e - sum(vote_es)) % evote.pub.n
    
    g_exp = (chal_e - sum(vote_es)) / evote.pub.n
    
    # Inverse if negative
    if g_exp < 0:
        g_term = inverse(pow(evote.pub.g, abs(g_exp), evote.pub.n), evote.pub.n)
    else:
        g_term = pow(evote.pub.g, g_exp, evote.pub.n)

    v_i = (ro * pow(evote.rand_num, e_i, evote.pub.n) * g_term) % evote.pub.n
    vote_vs[vote_i] = v_i
    vote_es[vote_i] = e_i

    # send e,v
    board.send(json.dumps({'e': vote_es, 'v': vote_vs}))

    result = board.recvline().strip()
    return result == 'PASS'


def cast_vote(gui=False, candidate=None):
    # We can only vote after registration closes
    board.send(make_cmd('regopen'))
    if parse_res(board.recvline()):
        return 'The election is not currently running'

    # Update the vote generator if needed
    if votegen.block_size is None:
        reg.send(make_cmd('count'))
        votegen.block_size = parse_res(reg.recvline()).bit_length()

    # Make sure we're logged in
    check_logged_in()
    if not gui:
        # Select the candidate you want
        print '\nSelect who you want to vote for:'
        while True:
            try:
                print candidate_menu
                candidate = int(raw_input('> ')) - 1
                assert 0 <= candidate < len(candidates)
                break
            except (ValueError, AssertionError):
                print 'Invalid choice'
    plain_vote = votegen.gen(candidate)
    enc_vote = board_key.encrypt(plain_vote)

    # Get a signature on our vote
    sig_vote = sign_vote(enc_vote)

    board.send(make_cmd('vote', {
        'name': login_user,
        'passhash': login_pass,
        'vote': enc_vote.ctxt,
        'signature': sig_vote
    }))
    
    # Check ZKPs
    try:
        print 'Hmmm, lookin\' kinda shady...'
        for attempt in xrange(ZKP_ROUNDS):
            # print attempt
            zkp_prove_knowledge(enc_vote, plain_vote)
        print 'Are You sure you\'re you?'
        for attempt in xrange(ZKP_ROUNDS):
            # print attempt
            zkp_prove_valid(enc_vote, plain_vote)
        print 'Huh, guess so.'
    except ValueError:
        return 'Vote not accepted'
    return parse_res(board.recvline())


def close_and_quit(gui=False):
    reg.send(make_cmd('quit'))
    board.send(make_cmd('quit'))
    reg.close()
    board.close()
    exit()

# Console interface
if __name__ == '__main__':
    funcs = [
        register_voter,
        login_voter,
        logout_voter,
        cast_vote,
        close_and_quit
    ]
    menu = ('Select Option:\n'
            "1) Register\n"
            "2) Login\n"
            "3) Logout\n"
            "4) Vote\n"
            "5) Quit")

    # Dat input loop
    while True:
        print '[----------------------------]'
        try:
            check_logged_in()
            print 'Logged in as: ' + login_user + '\n'
        except:
            pass
        print menu
        print '[----------------------------]'
        try:
            choice = int(raw_input('> ')) - 1
            assert 0 <= choice < len(funcs)
        except (ValueError, AssertionError):
            print 'Invalid choice'
            continue
        except KeyboardInterrupt:
            close_and_quit()

        try:
            print funcs[choice]()
        except LoginError:
            print 'Must be logged in'
        except SignError:
            print 'Error signing vote'
