# ThornChain
ThornChain is a simplistic cryptocurrency built in Golang in my spare time. The goal is to have a fully functional and independent peer to peer blockchain that can send and receive coins. The consensus mechanism utilised is Proof of Stake.

This is just a self education project to start learning about blockchain development.

## Current Features
 - HTTP server:
    - Current blockchain state is available at `localhost:8080/blocks`
    - Node's current peerstore is available at `localhost:8080/peers`
    - Find balance of an address at `localhost:8080/getbalance/{address}`
    - Write blocks via `POST` requests to `localhost:8080`
 - Peer to peer network:
    - Each node acts as a host and as a listener for other nodes
    - New nodes request a copy of the blockchain and peer store immediately
    - Blockchain state and peer store propagates among nodes
    - Orphaned nodes will try and reconnect to other nodes in the network
 - Proof of Stake:
    - Every node in the network is a potential block validator. The chance of being chosen to validate a block depends on the balance of the node's address (can be found under peer ID in `localhost:8080/peers`)
    - The winner is determined based on a random number generated with a seed. The seed for the random number generator is the hash of the previous block. This means that all nodes can perform the same calculation and reach the same result and use it to verify the validity of each block.
 - Basic blockchain functions:
    - Write blocks in JSON format in the console
    - Block hash calculations
    - Block generation
    - Block validations

The wallet/balance logic is pretty terrible at the moment, something to work on in the future.
## Block example
A JSON block structure can be sent to the node in either the console of the node or sent via `POST` request to `localhost:8080`. The other information such as block validator, hash and previous hash will automatically be recorded.

`{"from":"Microsoft","to": "IBM","amount":1000}`
## Installation
Unfortunately, I used a library that's fairly difficult to install/work with. The setup is more complicated than it should be, but the below steps should be good enough to follow.

Assuming you already have Golang installed:

1. Install go-libp2p. `go get -v -d github.com/libp2p/go-libp2p/...`
2. Navigate to the cloned directory above
3. Install package. `make`
4. Install dependencies. `make deps`
5. Navigate to where you want to install the development environment
6. Install the development environment. `go get -v -d github.com/libp2p/go-libp2p-examples`
7. Navigate into the go-libp2p-examples folder
8. Install ThornChain. `git clone https://github.com/ThornM9/ThornChain.git`
9. Install some random dependencies:
    - `go get -v -d github.com/gorilla/mux`
    - `go get -v -d github.com/davecgh/go-spew/spew`
    - `go get -v -d github.com/joho/godotenv`
10. Navigate into the ThornChain directory
11. Finally, run the node. `go run main.go`

With any luck, that should be it. Check current features for usage. 
