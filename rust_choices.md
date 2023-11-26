
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

 - use an mspc in client?
     - turn client into mspc select thing?
 - use an mspc in server to send many responses no block
 - figure out how to reduce serialization/deserialization. notably:
     - read/write data: store data and seqno together?

 - see if writer not caring about metadata helps perf
     - and or in-memory hashmap

 - do the SIG_AVOID thing
 - do all setup before sending back init ok lol 
 - implement subscriber
 - implement tests
 - implement benchmark


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


