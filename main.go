package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	golog "github.com/ipfs/go-log"
	"github.com/joho/godotenv"
	libp2p "github.com/libp2p/go-libp2p"
	crypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	net "github.com/libp2p/go-libp2p-net"
	peer "github.com/libp2p/go-libp2p-peer"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	ma "github.com/multiformats/go-multiaddr"
	gologging "github.com/whyrusleeping/go-logging"
)

type Block struct {
	Index     int
	Timestamp string
	From      string
	To        string
	Amount    int
	Hash      string
	PrevHash  string
}

var Blockchain []Block

var PeerStore []string

var mutex = &sync.Mutex{}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func calculateHash(block Block) string {
	record := string(block.Index) + block.Timestamp + string(block.From) + string(block.To) + string(block.Amount) + block.PrevHash
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func generateBlock(oldBlock Block, From string, To string, Amount int) (Block, error) {

	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.From = From
	newBlock.To = To
	newBlock.Amount = Amount
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Hash = calculateHash(newBlock)

	return newBlock, nil
}

func isBlockValid(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}

	if oldBlock.Hash != newBlock.PrevHash {
		return false
	}

	if calculateHash(newBlock) != newBlock.Hash {
		return false
	}

	return true
}

func replaceChain(newBlocks []Block) {
	if len(newBlocks) > len(Blockchain) {
		Blockchain = newBlocks
	}
}

func runLocalHost() error {
	mux := makeMuxRouter()
	httpAddr := os.Getenv("ADDR")
	log.Println("Listening on ", os.Getenv("ADDR"))
	s := &http.Server{
		Addr:           ":" + httpAddr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if err := s.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func makeMuxRouter() http.Handler {
	muxRouter := mux.NewRouter()
	muxRouter.HandleFunc("/", handleGetBlockchain).Methods("GET")
	muxRouter.HandleFunc("/", handleWriteBlock).Methods("POST")
	return muxRouter
}

func handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(Blockchain, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, string(bytes))
}

type Message struct {
	From   string
	To     string
	Amount int
}

func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	var m Message

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&m)
	log.Println(err)
	log.Println(m)
	if err != nil {
		respondWithJson(w, r, http.StatusBadRequest, r.Body)
		return
	}
	defer r.Body.Close()

	newBlock, err := generateBlock(Blockchain[len(Blockchain)-1], m.From, m.To, m.Amount)
	if err != nil {
		respondWithJson(w, r, http.StatusInternalServerError, m)
		return
	}

	if isBlockValid(newBlock, Blockchain[len(Blockchain)-1]) {
		newBlockchain := append(Blockchain, newBlock)
		replaceChain(newBlockchain)
		spew.Dump(Blockchain)
	}

	respondWithJson(w, r, http.StatusCreated, newBlock)
}

func respondWithJson(w http.ResponseWriter, r *http.Request, code int, payload interface{}) {
	response, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.WriteHeader(code)
	w.Write(response)
}

func makeBasicHost(listenPort int, randseed int64) (host.Host, error) {
	// Deterministic vs Random seed
	var reader io.Reader
	if randseed == 0 {
		reader = rand.Reader
	} else {
		reader = mrand.New(mrand.NewSource(randseed))
	}

	// Generate key pair
	priv, _, err := crypto.GenerateEd25519Key(reader)
	if err != nil {
		return nil, err
	}

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort)),
		libp2p.Identity(priv),
	}

	basicHost, err := libp2p.New(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	// build host multiaddress
	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", basicHost.ID().Pretty()))
	log.Println("-------------------------------------")
	log.Println(basicHost.Addrs())
	log.Println("-------------------------------------")
	// build a full address
	addr := basicHost.Addrs()[len(basicHost.Addrs())-1]
	fullAddr := addr.Encapsulate(hostAddr)
	log.Printf("I am %s\n", fullAddr)
	log.Printf("Now run \"go run main.go -l %d -d %s\" on a different terminal\n", listenPort+1, fullAddr)
	return basicHost, nil
}

func handleStream(s net.Stream) {

	log.Println("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	go readData(rw)
	go writeData(rw)

	// stream will stay open until closed by either side
}

func readData(rw *bufio.ReadWriter) {

	for {
		str, err := rw.ReadString('\n')
		if err != nil {
			log.Println("Lost a stream")
			break
		}

		if str == "" {
			return
		}
		if str != "\n" {
			chain := make([]Block, 0)
			newPeerStore := make([]string, 0)

			split := strings.Split(str, "zyx")
			if err := json.Unmarshal([]byte(split[0]), &chain); err != nil {
				log.Fatal(err)
			}

			if split[1] != "invalid\n" {
				if err := json.Unmarshal([]byte(split[1]), &newPeerStore); err != nil {
					log.Fatal(err)
				}

				for _, peer := range newPeerStore {
					if !stringInSlice(peer, PeerStore) {
						PeerStore = append(PeerStore, peer)
					}
				}
			}

			mutex.Lock()
			// CONSENSUS MECHANISM
			if len(chain) > len(Blockchain) {
				Blockchain = chain
				bytes, err := json.MarshalIndent(Blockchain, "", "  ")
				if err != nil {
					log.Fatal(err)
				}
				// Green console color: 	\x1b[32m
				// Reset console color: 	\x1b[0m
				fmt.Printf("\x1b[32m%s\x1b[0m> ", string(bytes))
			}
			mutex.Unlock()
		}
	}
}

func writeData(rw *bufio.ReadWriter) {

	go func() {
		for {
			time.Sleep(5 * time.Second)
			mutex.Lock()
			bytes, err := json.Marshal(Blockchain)
			if err != nil {
				log.Println(err)
			}
			var PeerBytes []byte
			if len(PeerStore) > 0 {
				log.Println(PeerStore)
				PeerBytes, err = json.Marshal(PeerStore)
				if err != nil {
					log.Println(err)
				}
			}
			mutex.Unlock()

			mutex.Lock()
			var sendString string
			if len(PeerStore) > 0 {
				sendString = string(bytes) + "zyx" + string(PeerBytes)
			} else {
				sendString = string(bytes) + "zyx" + "invalid"
			}
			rw.WriteString(fmt.Sprintf("%s\n", sendString))
			rw.Flush()
			mutex.Unlock()
		}
	}()

	stdReader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		sendData, err := stdReader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		msg := &Message{}
		fmt.Println(sendData)

		err = json.Unmarshal([]byte(sendData), msg)

		from := msg.From
		to := msg.To
		amount := msg.Amount

		newBlock, err := generateBlock(Blockchain[len(Blockchain)-1], from, to, amount)
		if err != nil {
			log.Fatal(err)
		}

		if isBlockValid(newBlock, Blockchain[len(Blockchain)-1]) {
			mutex.Lock()
			Blockchain = append(Blockchain, newBlock)
			mutex.Unlock()
		}

		bytes, err := json.Marshal(Blockchain)
		if err != nil {
			log.Println(err)
		}

		printBytes, err := json.MarshalIndent(Blockchain, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("\x1b[32m%s\x1b[0m> ", string(printBytes))

		mutex.Lock()
		rw.WriteString(fmt.Sprintf("%s\n", string(bytes)))
		rw.Flush()
		mutex.Unlock()
	}

}

func main() {
	// Load environment variables
	err := godotenv.Load("port.env")
	if err != nil {
		log.Fatal(err)
	}

	// Create Genesis block
	t := time.Now()
	genesisBlock := Block{0, t.String(), "ThornChain", "Thornton Personal", 1000000, "", ""}
	spew.Dump(genesisBlock)
	Blockchain = append(Blockchain, genesisBlock)

	// Set the verbosity of the libp2p logging
	golog.SetAllLoggers(gologging.INFO)

	// Parse options from the command line
	listenF := flag.Int("l", 0, "wait for incoming connections")
	target := flag.String("d", "", "target peer to dial")
	seed := flag.Int64("seed", 0, "set random seed for id generation")
	flag.Parse()

	if *listenF == 0 {
		log.Fatal("Please provide a port to bind on with -l")
	}

	// Make a host that listens on the given multiaddress
	host, err := makeBasicHost(*listenF, *seed)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(host)

	if *target == "" {
		log.Println("listening for connections")
		// Set a stream handler on host A. /p2p/1.0.0 is
		// a user-defined protocol name.
		host.SetStreamHandler("/p2p/1.0.0", handleStream)

		select {} // hang forever
		/**** This is where the listener code ends ****/
	} else {
		host.SetStreamHandler("/p2p/1.0.0", handleStream)

		// The following code extracts target's peer ID from the
		// given multiaddress
		ipfsaddr, err := ma.NewMultiaddr(*target)
		if err != nil {
			log.Fatalln(err)
		}

		pid, err := ipfsaddr.ValueForProtocol(ma.P_IPFS)
		if err != nil {
			log.Fatalln(err)
		}

		peerid, err := peer.IDB58Decode(pid)
		if err != nil {
			log.Fatalln(err)
		}

		// Decapsulate the /ipfs/<peerID> part from the target
		// /ip4/<a.b.c.d>/ipfs/<peer> becomes /ip4/<a.b.c.d>
		targetPeerAddr, _ := ma.NewMultiaddr(
			fmt.Sprintf("/ipfs/%s", peer.IDB58Encode(peerid)))
		targetAddr := ipfsaddr.Decapsulate(targetPeerAddr)

		// We have a peer ID and a targetAddr so we add it to the peerstore
		// so LibP2P knows how to contact it
		host.Peerstore().AddAddr(peerid, targetAddr, pstore.PermanentAddrTTL)
		log.Println("HOST PEERSTORE")
		peers := host.Peerstore().PeersWithAddrs()
		for _, peer := range peers {
			PeerStore = append(PeerStore, host.Peerstore().Addrs(peer)[0].String())
		}

		log.Println("opening stream")
		// make a new stream from host B to host A
		// it should be handled on host A by the handler we set above because
		// we use the same /p2p/1.0.0 protocol
		s, err := host.NewStream(context.Background(), peerid, "/p2p/1.0.0")
		if err != nil {
			log.Fatalln(err)
		}
		// Create a buffered stream so that read and writes are non blocking.
		rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

		// Create a thread to read and write data.
		go writeData(rw)
		go readData(rw)

		select {} // hang forever

	}

	// Run the browser localhost
	// log.Fatal(runLocalHost())

}
