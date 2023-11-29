
# Rust technology choices

## Serialization/Deserialization

I started with protobufs (specifically tokio's [prost](https://crates.io/crates/prost) libary), but ended up using serde+[postcard](https://crates.io/crates/postcard) because they made things easy.
Protobufs are hard because all the fields are optional (in the interest of backwards-compatibility), which
means that the application code needs to manually check each field to make sure it was set. After writing
some code like that for around 10 minutes, I gave up and switched to postcard. Postcard is also made to be very efficient which is a nice bonus.

Code [here](./rustdc/src/request.rs).


## Data Storage (local storage)

A natural choice would be RocksDb (to match the master's thesis implementation), but I think sled (https://sled.rs/) is
a better choice. The only iffy part about sled is that their API is sync (not async), but apparently that's an intentional performance choice.

The sled developers also made a very nice blog but that did not influence my decision.

## Data Storage (remote storage)

I think DynamoDB would be my choice for a "remote" storage implementation (I think s3 was suggested but s3 is not
really meant to be a database). However, have not given this much thought.


## Cryptography

[OpenSSL](https://docs.rs/openssl/latest/openssl/) would match the master's thesis. It's also the most
used cryptography library of all time.

Code [here](./rustdc/src/crypto.rs) (TODO: have not actually bound to openSSL types yet)

Crypto benchmarks:
 - signing: used `Nid::X9_62_PRIME256V1` and `EcdsaSig::sign(b"I like cheese and bread and butter", &key)?.to_der()?`,
   the signing took `115.389µs`. I think the signatures may have been an exaggeration.
 - verifying: verifying took 50µs.




## Executor

Tokio seems like the natural choice for network stuff. However, we have some things that are non-ideal for Tokio:
 - we have some CPU-bound operations (all the cryptography stuff)
 - Sled has a sync interface

So Tokio may not be ideal here. We could switch completely to threads (if we assume a small number of
clients to the datacapsule server), or we could make a thread pool (maybe Rayon?) for processing
requests.


# Optimization TODOs:

 - use an mspc in server to send many responses no block
 - figure out how to reduce serialization/deserialization


 - do the SIG_AVOID thing
 - implement subscriber
 - implement tests
 - implement benchmark


 - clients should tokyo spawn 

# Benchmark numbers

100000 write (no commit): 
```
know keys: 91 91
Did setup in 4.385215ms. DC: [40, ce, ca, ef, 3e, c6, 67, 82, 3d, 93, de, 29, 4f, 35, 6e, c2, 72, 35, 16, 91, 87, 0, c4, 20, 4f, e2, c3, 6d, a2, bd, 84, e5]
hiyo: 351.116409ms
hiya: 277.848008ms
Did writes in 629.655644ms. got 100000
```
so 6.29 microseconds per write

100000 write (with commit):
```
know keys: 91 91
Did setup in 4.44992ms. DC: [3c, 1e, 29, de, b2, 33, 5a, 53, 66, 92, 8e, 7c, 5e, e6, 5a, 11, c5, fe, 50, ae, 7b, 9f, 53, ce, 1c, 7c, af, db, 8, fe, 96, a5]
root time: 15.263268ms
hiyo: 380.720155ms
hiya: 784.598702ms
Did writes in 1.166117878s. got 100001

root time: 24.522577ms
store records: 418.036622ms
store treenodes: 155.857782ms
```

a million writes and reads (with commit, no proofs):
```
know keys: 91 91
Did setup in 4.324286ms. DC: [b2, 8, b8, 8f, a0, ae, e1, 82, a2, 18, 5a, 81, b0, c5, bd, 27, 16, 69, c0, 99, 67, 52, ff, 21, c2, 21, ea, 37, d5, 90, 12, 97]
Did writes in 15.307566789s. got 1000001
Did reads in 2.318867792s. got 1000000
```



# Major TODOs:

 - (sam) actually implement stuff. Tentative order:
     - hash cache (done)
     - merkle trees (done)
     - serialization/deserialization (done)
     - local data storage
     - cryptography
     - tokio networking stuff
     - client library
     - server executable
 - (someone else) research how to do dynamoDB stuff from Rust. Probably involves setting up an AWS account which will be painful
 - (someone else) get the master's thesis implementation up and running
 - (someone else) Write 2 high level clients (one in Rust, using our low-level client, and one using the master's thesis cpp client). These high-level clients should have the same high-level interface, even though our low-level clients have quite different interfaces. Then, write benchmarks that use the clients. 


