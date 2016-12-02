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

    try:
        check_logged_in()
        print 'Already Logged In'
        return
    except:
        pass

    # We can only register in the registration phase
    board.send(make_cmd('regopen'))
    if not parse_res(board.recvline()):
        print 'Registration is currently closed'
        return

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
    print parse_res(reg.recvline())


def login_voter(gui=False, user=None, password=None):
    global login_user, login_pass
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
        print 'Successfully logged in as \'' + args['name'] + '\''
    else:
        print 'Could not login'


def logout_voter(gui=False):
    check_logged_in()
    global login_user, login_pass
    login_user = login_pass = None
    print 'Logged out'
   
def sign_vote(vote):
    # type: (paillier.EncryptedMessage) -> long
    # Blind and send our encrypted vote
    
    check_logged_in()
    blind_r = getRandomRange(2, reg_key.n)
    blinded_vote = (vote.ctxt * pow(blind_r, reg_key.e, reg_key.n)) % reg_key.n
    reg.send(make_cmd('sign', {
        'name': login_user,
        'password': login_pass,
        'vote': blinded_vote
    }))

    # Get the signed vote and undo the blinding
    try:
        signed = (parse_res(reg.recvline()) / blind_r) % reg_key.n
        assert signed == vote.ctxt
        return signed
    except (ValueError, AssertionError):
        raise SignError()


def zkp_prove_knowledge(evote, pvote):
    # type: (paillier.EncryptedMessage, long) -> bool

    # choose r in Zn
    know_r = getRandomRange(0, evote.pub.n)
    # choose s in Zn star
    know_s = getRandomRange(0, evote.pub.n)
    while GCD(know_s, evote.pub.n) != 1:
        know_s = getRandomRange(0, evote.pub.n)
    # calc u
    know_u = (evote.pub.g ** know_r * know_s ** evote.pub.n) % evote.pub.n_sq
    # send u
    board.send(str(know_u))

    # receive e
    know_e = long(board.recvline())

    # calc v, w
    know_v = (know_r - know_e * pvote) % evote.pub.n
    know_w = (know_s * inverse(evote.rand_num, evote.pub.n) ** know_e) % evote.pub.n

    board.send(str(know_v) + "," + str(know_w))
    result = board.recvline()
    if result != "PASS":
        return False

    return True


def zkp_prove_valid(evote, pvote):
    # type: (paillier.EncryptedMessage), (long) -> None
    vote_set = map(votegen.gen, xrange(votegen.num_cands))
    vote_i = vote_set.index(pvote)
    ro = getRandomRange(0, evote.pub.n)
    while GCD(ro, evote.pub.n) != 1:
        ro = getRandomRange(0, evote.pub.n)
    vote_es = []
    vote_vs = []
    vote_us = []
    for j in xrange(votegen.num_cands):
        if j == vote_i:
            vote_es.append(0)
            vote_vs.append(0) 
            vote_us.append((ro**evote.pub.n) % evote.pub.n_sq)
            continue
        
        e_j = getRandomRange(0, evote.pub.n)
        votes_es.append(e_j)

        v_j = getRandomRange(0, evote.pub.n)
        while GCD(v_j, evote.pub.n) != 1:
            v_j = getRandomRange(0, evote.pub.n)
        vote_vs.append(v_j)
        
        u_j = (v_j**evote.pub.n*(evote.pub.g*inverse(evote.ctxt, evote.pub.n_sq))**e_j) % evote.pub.n_sq
        vote_us.append(u_j)

    # send u's

    # receive e
    chal_e = 13224

    e_i = (chal_e - sum(vote_es)) % evote.pub.n
    vote_es[vote_i] = e_i

    v_i = (ro*evote.rand_num**e_i*evote.pub.g**((chal_e - sum(vote_es))/evote.pub.n)) % evote.pub.n
    vote_vs[vote_i] = v_i

    # send e,v


def cast_vote(gui=False, candidate=None):
    # We can only vote after registration closes
    board.send(make_cmd('regopen'))
    if parse_res(board.recvline()):
        print 'The election is not currently running'
        return

    # Update the vote generator if needed
    if votegen.block_size is None:
        reg.send(make_cmd('count'))
        votegen.block_size = parse_res(reg.recvline())

    # Make sure we're logged in
    check_logged_in()
    if not gui:
        # Select the candidate you want
        print '\nSelect who you want to vote for:'
        while True:
            try:
                candidate = int(raw_input('> ')) - 1
                assert 0 <= candidate < len(candidates)
                break
            except (ValueError, AssertionError):
                print 'Invalid choice'
    
    plain_vote = votegen.gen(candidate)
    enc_vote = board_key.encrypt(plain_vote)

    # Get a signature on our vote
    sig_vote = sign_vote(enc_vote)


def close_and_quit(gui=False):
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
            funcs[choice]()
        except LoginError:
            print 'Must be logged in'
        except SignError:
            print 'Error signing vote'
