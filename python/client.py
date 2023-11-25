import socket 
import threading
import protos.requests_pb2 as requests_pb2
import protos.storage_pb2 as storage_pb2
import random


def init_client(conn_type = "read", datacapsule_hash = None):
    metadata = {}
    # Connection Data / Server Information
    host = '127.0.0.1'
    port = 22222

    # Starting Server (TODO: check that client isn't already connected)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    client.connect(server_address)

    init_req = requests_pb2.InitRequest()
    init_req.type = conn_type
    if conn_type != "read":
        init_req.datacapsule_hash = datacapsule_hash
    client.send(init_req.SerializeToString())
    data = client.recv(1024)
    response = requests_pb2.InitResponse()
    response.ParseFromString(data)
    if not response.init_success:
        print("Connection failed")
        client.close()
    else:
        print("Connected to server!!!!")
        


if __name__ == "__main__":
    init_client()