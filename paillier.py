#!/usr/bin/env python2
"""
Simple Paillier encryption library
"""

from Crypto.Util.number import inverse, getStrongPrime, getRandomRange, GCD


class PublicKey:
    """
    Contains a Paillier public key (modulus, generator) and allows for encryption
    """

    def __init__(self, n):
        self.n = n
        self.n_sq = n * n  # Just for convenience / no need to recalculate
        self.g = n + 1  # Works because p, q are the same size

    def encrypt(self, ptxt):
        """ Encrypts the given plaintext using this public key

        Args:
            ptxt (long): The numeric representation of the plaintext to be encrypted

        Returns:
            EncryptedMessage: The resulting encryption
        """
        if not isinstance(ptxt, (int, long)):
            raise TypeError('Plaintext must be a number')

        r = random_range_coprime(2, self.n, self.n)
        ctxt = (pow(self.g, ptxt, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        return EncryptedMessage(self, ctxt, r)

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            return self.n == other.n and self.g == other.g
        return False

    def __ne__(self, other):
        return not (self == other)


class PrivateKey:
    """
    Contains all key components for Paillier encryption/decryption
    """

    def __init__(self, pub, p, q):
        self.pub = pub
        self.lm = (p - 1) * (q - 1)
        self.mu = inverse(self.lm, pub.n)

    def decrypt(self, c):
        """ Decrypts the given ciphertext using this private key

        Args:
            c (long, EncryptedMessage): The ciphertext to be decrypted

        Returns:
            long: Numeric representation of the decrypted plaintext
        """
        if isinstance(c, EncryptedMessage):
            if c.pub != self.pub:
                raise ValueError("Public keys don't match")
            c = c.ctxt

        if not isinstance(c, (int, long)):
            raise TypeError('Ciphertext must be a number')

        return (((pow(c, self.lm, self.pub.n_sq) - 1) / self.pub.n) * self.mu) % self.pub.n


class EncryptedMessage:
    """
    Wrapper around a Paillier ciphertext to add more functionality
    """

    def __init__(self, pub, ctxt, r=None):
        self.pub = pub
        self.ctxt = ctxt
        self.rand_num = r  # Keeps track of the random number used for encryption (for ZKP)

    def __add__(self, other):
        """ Adds another encrypted message or plaintext to this one

        Args:
            other (long, EncryptedMessage): The value to be added to this one

        Returns:
            EncryptedMessage: If another encrypted message is given, the result will
            decrypt to the sum of the two decrypted plaintext. If given a scalar value,
            the result will decrypt to the sum of this plaintext and the given value.
        """
        add_val = 1
        if isinstance(other, EncryptedMessage):
            if self.pub != other.pub:
                raise ValueError("Public keys don't match")
            # To add two ctxts we just multiply them together
            add_val = other.ctxt
        elif isinstance(other, (int, long)):
            # To add an int k, we multiply by g^k
            add_val = pow(self.pub.g, other % self.pub.n_sq, self.pub.n_sq)

        return EncryptedMessage(self.pub, (self.ctxt * add_val) % self.pub.n_sq)

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        return self + -other

    def __mul__(self, other):
        """ Multiplies this encrypted text by a scalar value

        Args:
            other (long): Value to mutliply this encrypted message by

        Returns:
            EncryptedMessage: An encrypted message that decrypts to this plaintext
            multiplied by the given scalar value

        """
        if not isinstance(other, (int, long)):
            raise TypeError('Encrypted message must be multiplied by a number')

        return EncryptedMessage(self.pub, pow(self.ctxt, other % self.pub.n_sq, self.pub.n_sq))

    def __rmul__(self, other):
        return self * other

    def __neg__(self):
        return self * -1


def gen_keypair(nbits=2048):
    """ Generates a public/private key pair for Paillier encryption

    Args:
        nbits (int): Desired bit length of the modulus

    Returns:
        pub (PublicKey): Public key used for encryption
        priv (PrivateKey): Private key associated with the public key, used for decryption
    """
    p = getStrongPrime(nbits / 2)
    q = getStrongPrime(nbits / 2)
    pub = PublicKey(p * q)
    return pub, PrivateKey(pub, p, q)


def random_range_coprime(a, b, n):
    """
    Generates a random value r in the range a <= r < b, with r being coprime to n
    (aka Z star)

    Args:
        a (long): Lower bound
        b (long): Upper bound
        n (long): Modulus

    Returns:
        A random value r in the given range such that GCD(r, n) == 1
    """
    res = getRandomRange(a, b)
    while GCD(res, n) != 1:
        res = getRandomRange(a, b)
    return res
