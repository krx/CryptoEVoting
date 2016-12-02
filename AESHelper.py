from Crypto.Cipher import AES


def encrypt(data, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data))


def decrypt(data, key, iv):
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data))


def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)


def unpad(s):
    return s[0:-ord(s[-1])]
