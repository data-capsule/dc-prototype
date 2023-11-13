from utils import *




class DCMetadata():
    pass



class Connection():
    def __init__(self, address: str):
        pass

    def send(self, msg: bytes):
        pass

    def rcv(self) -> bytes:
        return b'weofik'


def create(self, address: str, server_pub_key: bytes, dc: DCMetadata,
            sym_key: bytes, sig_pri_key: bytes, sig_pub_key: bytes):
    self.connection = Connection(address)
    self.server_pub_key = server_pub_key
    self.dc_name = dc.name
    self.sym_key = sym_key
    self.sig_pri_key = sig_pri_key
    self.sig_pub_key = sig_pub_key

    self.connection.send("I would like to create this DC: " + dc)


class WriterClient():
    def __init__(self, address: str, server_pub_key: bytes, dc_name: bytes,
             sym_key: bytes, sig_pri_key: bytes):
        self.connection = Connection(address)
        self.server_pub_key = server_pub_key
        self.sym_key = sym_key
        self.sig_pri_key = sig_pri_key
        self.uncommitted_hashes = []

        self.connection.send("I would like to write to " + dc_name)
        # TODO: sign random numbers to verify connection is fine?

    def write(self, data: bytes):
        pass

    def commit(self):
        pass



class ReaderClient():
    def __init__(self, address: str, dc_name: bytes, sym_key: bytes, sig_pub_key: bytes):
        self.connection = Connection(address)
        self.sym_key = sym_key
        self.hashcache = HashCache()
        self.last_rcvd_hashes = [b'0000000'] * FANOUT
        self.unproved_reads = []
        self.sig_pub_key = sig_pub_key

        self.connection.send("I would like to read " + dc_name)

    def read(self, record_name) -> bytes:
        self.connection.send(record_name)
        proofanddata = self.connection.rcv()

        ret = b''
        for thing in proofanddata:
            if is_signature(thing):
                hash = 123123 # extract
                verify_signature(hash, signature, self.sig_pub_key)
                self.hashcache.store(self.last_rcvd_hashes[0])
                self.last_rcvd_hashes[0] = hash
            elif is_hashblock(thing):
                blockhash = create_hash(thing)
                self.verify_hash(blockhash)
                for h in self.last_rcvd_hashes:
                    self.hashcache.store(h)
                self.last_rcvd_hashes = thing
            else: # data
                hash = create_hash(thing)
                self.verify_hash(hash)
                ret = thing
        return decrypt(ret, self.sym_key)

    def prove(self, record_name) -> bool:
        self.connection.send("plz prove")
        proofanddata = self.connection.rcv()


    def verify_hash(self, hash):
        good = False
        for h in self.last_rcvd_hashes:
            if h == hash:
                good = True
                break
        if not (good or self.hashcache.contains(hash)):
            self.hashcache.clear()
            self.last_rcvd_hashes = [b'0000000'] * FANOUT
            raise Exception("failed to verify hash")
