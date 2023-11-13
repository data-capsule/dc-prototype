# Datacapsule Storage Server Design

## Basics


This design assumes single-writer.

## Terminology

 - Client: a client
 - Server: a server
 - Connection: see [initializing a connection](#initializing-a-connection). A Client
   and server may have multiple connections.
 - Datacapsule: an append-only datastructure, which may have multiple replicas on different servers
 - Record: a unit of data within a Datacapsule. Each record is encrypted with a [TODO] symmetric key.
 - Hash: a [TODO] hash. Hashes also serve as the names of things in this design. For example, datacapsules and records are both named by their hashes.
 - Signed Hash: a [TODO] hash, and a [TODO] signature of the hash.
 - Null Hash: 16 bytes of 0. This represends a missing hash (for example, unused branches of a
   Merkle tree).
 - Message: A Protobuf message, sent between client and server over a TCP connection.
 - Commit: A group of records that are signed with one [TODO] signature (the signature signs the hash at the root of a Merkle tree, whose leaves are the encrypted records).
 - Hash block: A group of hashes, representing one node in a Merkle tree. How many hashes depends on the fanout of the Merkle tree. For example, in a binary Merkle tree, a hash block is just a pair of hashes



## Initializing a connection

Connections are TCP connections, which maintain byte streams going in both directions. At the start of a connection, the client sends the server a message, describing what type of connection it wants to create. In the case of write/read/subscribe connections, it also sends the hash of the datacapsule that it wants.

Message format: see [init.proto](./protos/requests/init.proto).

## "Creator" connection

A creator's main purpose is to create new Datacapsules. This type of connection should be rare, and usually short-lived. It has just one operation:

 - `createDatacapsule(writer_pub_key, description) -> bool` creates a new datacapsule on the server. After this operation, the server should accept write/read/subscribe connections to this datacapsule.

Message format: see [create.proto](./protos/requests/create.proto).

## "Writer" connection

A writer's main purpose is to append new records to a datacapsule. For each writer connection, the client and the server both maintain a list of hashes of uncommitted records. A writer has two operations:

 - `write(data)` prepends a nonce (see [duplicate records](#duplicate-records)), encrypts a record, then sends the record to the server.
 - `commit(hash) -> signedhash` creates a Merkle tree of hashes of the uncommitted
   records. This also includes an additional hash, which may be the root hash
   of the previous commit. The additional hash is optional; it exists mainly
   for efficiency of read operations. The client sends the server a signed hash
   of the root of the Merkle tree. 
    - Success: The server verifies that the signed hash is
      valid, then sends back a signed hash of the root of the Merkle tree. The
      Merkle tree and records are stored on the server, and the server updates
      its linked list of records to advertise to subscribers (see [subscriber connection](#subscriber-connection)).
    - Failure: If the server's hash does not match, or the signature is invalid,
      or the server's signature is invalid, or the connection is broken before
      the commit operation, the entire commit is aborted. This means the data
      is unwritten and and the list of uncommitted records is reset. The server
      sends back an empty message to notify the client of the failure. If the
      client wants to try again, they must replay all the writes and the commit
      operation.

Message format: see [write.proto](./protos/requests/write.proto).

## "Reader" connection

A reader's main purpose is to get the data for any records that it knows about.
For each reader connection, the client and the server both maintain two things:
 - a "Hash Cache" that stores some proven hashes. There are no particular
   requirements for the hash cache, as long as it has the exact same behavior
   between client and server. One implementation could be a 1024 element 
   direct-mapped cache.
 - the contents of the last proven hash block (this starts out as a bunch of
   null hashes). This ensures that each element of a proof can depend on the
   previous element.


A reader has two operations:
 - `read(hash) -> data` fetches the encrypted contents of a record with the
   given hash. The data is decrypted and the nonce discarded.
 - `prove(hash) -> bool` fetches a proof for the record with the given hash. A
   proof takes the following form:
     - optionally, a signed hash (signed by the datacapsule's writer). This may
       not be included if the root of the proof is in the hash cache. If it is
       included and the signature is valid, the last proven hash block is moved
       to the hash cache, and this hash becomes the last proven hash block.
     - zero or more hash blocks. Each hash block is valid if its hash is in the
       cache, or in the last proven hash block. If it is valid, it becomes the
       last proven hash block, and the previous last proven hash block is
       moved to the cache.
   at the end of the proof, the given hash must be present in the last proven
   hash block or in the hash cache. If not, the proof is invalid.

Message format: see [read.proto](./protos/requests/read.proto).

The purpose of the hash cache is to allow records in the same commit (or across multiple, close together commits) to be proven with as few signatures / hashes as possible. In the extreme case, imagine an infinite cache. This would allow an entire commit to be proven with the signature and each hash block transmitted just once. We use a fixed size cache to make sure clients can never get overwhelmed.

It might seem silly to separate this into two operations: after all, when will
a reader not immediately request a proof after reading a record? There are a few
cases:
 - If multiple clients are working together (i.e. a secure enclave), and they
   all need some common data, only one of them needs to prove that the data is
   valid.
 - If a client reads records across multiple commits, it often reads records in
   order of oldest to newest. However, proofs across multiple commits are most
   efficient in order of newest to oldest (a newer commit contains a hash of the
   previous commit, thus allowing both to be proven with just the newer commit's
   signature). Therefore, an efficient pattern could be:
   ```python
   for record in list_of_records:
       read(record)
   for record in list_of_records[::-1]:
       assert(prove(record))
   ```



## "Subscriber" connection

A subscriber's main purpose is to discover when new records are written to a
datacapsule. It has two operations:

 - `get_last_hash() -> hash` gets the hash of the last written record to the
    datacapsule for this storage server. Note that two different servers may
    return different results, even if they contain the same data, if they
    received the data in a different order.
 - `get_after(hash) -> hash` gets the hash of the record succeeding the given
    hash. If the given hash is the latest one, this operation will block until
    a new record is available. 

Message format: see [subscribe.proto](./protos/requests/subscribe.proto).

A common pattern is to call `get_after` in a loop to get new updates:

```python
hash = get_last_hash()
while True:
    hash = get_after(hash)
    print(f"New record: {hash}")
```



## Configurable parameters

Some things that can be played around with:
 - the fanout of the Merkle tree (a higher fanout means more data transmitted over the wire per proof, but better use of the cache)
 - the size and design of the "hash cache"
 - "signature avoidance": how many extra hashes the server is willing to send
   in order to avoid sending a signature. Depends on ratio of how expensive it
   is to compute a hash vs verify a signature.

## Edge cases

### Duplicate records

Multiple records may have the same content, thus leading to the same hash. By proxy,
this means that multiple hash blocks may be equivalent as well. There a couple
things that could be done:
 - Client: prepend a 16-byte random nonce to each record, since the existence of duplicates
   leaks information 
 - Server: make sure implementation correctly handles duplicates, since client
   may be uncooperative and not actually prepend a random nonce. 
The server does not have to provide any guarantees to the client, since any
duplicates are the client's fault.

### Ordering

When a datacapsule is replicated, the order of its elements may differ across
servers. Therefore it may not be relied on.

## Storage Schema

I think they want key-value store interface, but a relational database design might better fit our needs.

Initial plan: each datacapsule gets a separate set of tables. Each data capsule gets:


 - stored in a file/memory:
     - creator pub key
     - creator signature
     - writer pubkey
     - description
     - latest block
 - stored in a file? A bunch of binary data (essentially use it as a huge array)
 - datablocks table
     - hash (primary key)
     - hash of parent
     - hash of next block
     - index+length of data
 - treeblocks: 
     - hash of children (primary key)
     - hash of parent
     - whether this treeblock is signed
     - hash of each child
 - sigblocks
     - hash of treeblock (primary key)
     - signature
