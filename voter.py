#!/usr/bin/env python2

import paillier
from common import *
from hashlib import sha256
from Crypto.Util.number import getRandomRange, GCD, inverse

# Connect to registrar
reg = RSASocket()
reg.connect((HOST, PORT_REGISTRAR))

# Get the registrar's public key
reg.send(make_cmd('key'))
reg_key = parse_res(reg.recvline())
reg_key = RSA.construct((long(reg_key['n']), long(reg_key['e'])))

# Connect to board
board = RSASocket()
board.connect((HOST, PORT_BOARD))

# Get the board's public key
board.send(make_cmd('key'))
board_key = paillier.PublicKey(parse_res(board.recvline()))

# Get the list of candidates
board.send(make_cmd('candidates'))
candidates = parse_res(board.recvline())
candidate_menu = '\n'.join(['{}) {}'.format(i + 1, cand) for i, cand in enumerate(candidates)])

# Keep track of the current user
login_user = login_pass = None


class LoginError(Exception): pass
class SignError(Exception): pass


def check_logged_in():
    # These are only ever set once the registrar is okay with it
    if login_user is None or login_pass is None:
        raise LoginError()


def register_voter():
    global login_user, login_pass
    # We can only register in the registration phase
    board.send(make_cmd('regopen'))
    if not parse_res(board.recvline()):
        print 'Registration is currently closed'
        return

    args = {
        'name': raw_input('Enter name: '),
        'password': sha256(raw_input('Enter password: ')).hexdigest()
    }
    reg.send(make_cmd('register', args))
    res = parse_res(reg.recvline())
    print res

    if 'Success' in res:
        login_user = args['name']
        login_pass = args['password']


def login_voter():
    global login_user, login_pass
    pass


def logout_voter():
    global login_user, login_pass
    login_user = login_pass = None


def sign_vote(vote):
    # type: (paillier.EncryptedMessage) -> long
    # Blind and send our encrypted vote
    blind_r = getRandomRange(2, reg_key.n)
    blinded_vote = (vote.ctxt * pow(blind_r, reg_key.e, reg_key.n)) % reg_key.n
    reg.send(make_cmd('sign', {
        'name': login_user,
        'password': login_pass,
        'vote': blinded_vote
    }))

    # Get the signed vote and undo the blinding
    try:
        return (parse_res(reg.recvline()) / blind_r) % reg_key.n
    except ValueError:
        raise SignError()


def zkp_prove_knowledge(evote, pvote):
    # type: (paillier.EncryptedMessage), (long) -> bool

    # choose r in Zn
    know_r = getRandomRange(0, evote.pub.n)
    # choose s in Zn star
    know_s = getRandomRange(0, evote.pub.n)
    while GCD(know_s, evote.pub.n) != 1:
        know_s = getRandomRange(0, evote.pub.n)
    # calc u
    know_u = (evote.pub.g**know_r*know_s**evote.pub.n) % evote.pub.n_sq
    # send u
    board.send(str(know_u))

    # receive e
    know_e = long(board.recvline())

    # calc v, w
    know_v = (know_r - know_e*pvote) % evote.pub.n
    know_w = (know_s*inverse(evote.rand_num, evote.pub.n)**know_e) % evote.pub.n

    board.send(str(know_v) + "," + str(know_w))
    result = board.recvline()
    if result != "PASS":
        return False

    return True


def zkp_prove_valid(vote):
    # type: (paillier.EncryptedMessage) -> None
    pass


def cast_vote():
    # We can only vote after registration closes
    board.send(make_cmd('regopen'))
    if parse_res(board.recvline()):
        print 'The election is not currently running'
        return

    # Make sure we're logged in
    check_logged_in()

    # Select the candidate you want
    print '\nSelect who you want to vote for:'
    while True:
        try:
            candidate = candidates[int(raw_input('> ')) - 1]
        except ValueError:
            print 'Invalid choice'

            # Get a signature on our vote
            # sigvote = sign_vote()


def close_and_quit():
    reg.send(make_cmd('quit'))
    board.send(make_cmd('quit'))
    reg.close()
    board.close()
    exit()


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

    while True:
        print menu

        try:
            choice = int(raw_input('> ')) - 1
            assert 0 <= choice < len(funcs)
        except (ValueError, AssertionError):
            print 'Invalid choice'
            continue

        try:
            funcs[choice]()
        except LoginError:
            print 'Must be logged in'
        except SignError:
            print 'Error signing vote'
