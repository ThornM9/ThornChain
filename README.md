# ThornChain
ThornChain is a simplistic cryptocurrency built in Golang in my spare time. The goal is to have a fully functional and independent peer to peer blockchain that can send and receive coins. The consensus mechanism utilised is Proof of Stake.

This is just a self education project to start learning about blockchain development.

## Current Features
Currently, the blockchain is only available on localhost. 

 - Blockchain state available in browser
 - Block hash calculations
 - Block generation
 - Block validations
 - Write blocks via `POST` requests

## Installation
1. Navigate to a directory where you want to install ThornChain
2. `git clone https://github.com/ThornM9/ThornChain.git`
3. `go run main.go`
4. Open your browser and navigate to `http://localhost:8080/` to see the state of the blockchain
5. To write new blocks, send a  `POST`  request (Postman is good) to  `http://localhost:8080/`  with a JSON payload with `from`, `to` and `amount` as keys and a string, a string and an integer as the data types for the respective values. For example:
`{"from":"Microsoft","to": "IBM","amount":1000}`
A response will be sent containing the new block data in JSON form.
6. Refresh the browser to see the new additions to the blockchain.
