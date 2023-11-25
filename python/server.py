import socket 
import threading
import protos.requests_pb2 as requests_pb2
import protos.storage_pb2 as storage_pb2
import random

# assume this object does not go down


def main():
    # should be a K-V proto stored on AWS
    metadata = {}
    # Connection Data
    host = '127.0.0.1'
    port = 22222

    # Starting Server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()

    #clients = []

    receive(server)

def receive(server):
    while True:
        # Accept Connection
        client, address = server.accept()
        print("Connected with {}".format(str(address)))

        #clients.append(client)

        # Print And Broadcast Nickname
        #client.send('Connected to server!'.encode('ascii'))
        

        # Start Handling Thread For Client
        thread = threading.Thread(target=accept_connections, args=(client,))
        thread.start()

def accept_connections(client):
    while True:
        data = client.recv(1024)
        request = requests_pb2.InitRequest()
        request.ParseFromString(data)
        connection_type = request.type
        datacapsule_hash = None
        conn_func = {0: create_connection, 1: write_connection, 2: read_connection, 3: subscribe_connection}
        if connection_type > 0:
            datacapsule_hash = request.datacapsule_hash
        thread = threading.Thread(target=conn_func[connection_type], args=(client, datacapsule_hash,))
        thread.start()
        response = requests_pb2.InitResponse()
        response.init_success = True
        client.send(response.SerializeToString())

def create_connection(client, hash):
    data = client.recv(1024)
    request = requests_pb2.CreateRequest()
    request.ParseFromString(data)

    
    #message CreateRequest {
    #bytes creater_pub_key = 1;
    #bytes writer_pub_key = 2;
    #string description = 3;
    #SignedHash creater_signature = 4;


def write_connection(client, hash):
    data = client.recv(1024)
    request = requests_pb2.CreateRequest()
    request.ParseFromString(data)
    data = client.recv(1024)
    #Check message type
    #If write, handle with write function (below)
    #If commit, handle with commit function



def write():
    pass

def commit():
    pass

def read_connection(client, hash):
    data = client.recv(1024)
    request = requests_pb2.CreateRequest()
    request.ParseFromString(data)

def subscribe_connection(client, hash):
    data = client.recv(1024)
    request = requests_pb2.CreateRequest()
    request.ParseFromString(data)

if __name__ == "__main__":
    main()











