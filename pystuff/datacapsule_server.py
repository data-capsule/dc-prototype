from dataclasses import dataclass
from utils import *






@dataclass
class StoredDataCapsule:
    creator_pub_key: bytes
    writer_pub_key: bytes
    description: string
    


class FakeStorageLayer:
    def __init__(self) -> None:
        pass

    def store_data_block(self, dhash, hash, data):
        pass

    def load_data_block(self, dhash, hash) -> bytes:
        pass





