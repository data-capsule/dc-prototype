


FANOUT = 5


def create_hash(data: bytes) -> bytes:
    return b'this is a hash'

def encrypt(data: bytes, symmetric_key: bytes):
    return data + b'_encrypted';

def decrypt(data: bytes, symmetic_key: bytes):
    return data[:-10]

def sign(data: bytes, signing_private_key: bytes) -> bytes:
    return b'this is a signature'

def verify_signature(data: bytes, signature: bytes, signing_public_key: bytes):
    return True


class HashCache():
    """
    A 2-way set-associative cache
    
    """
    def __init__(self):
        pass

    def store(self, hash: bytes):
        pass

    def contains(self, hash: bytes) -> bool:
        pass

    def clear(self):
        pass
