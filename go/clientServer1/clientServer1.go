package main

/*
#cgo CFLAGS: -O2
#cgo LDFLAGS: -lcrypto -lm
#include "../../crypto_tools.h"
#include "../../shared_franking.h"
#include "../../crypto_tools.c"
#include "../../shared_franking.c"
*/
import "C"
import (
    "log"
    "crypto/tls"
    "net"
    "os"
    "time"
    "unsafe"
    //"io"
    "crypto/rand"
    "golang.org/x/crypto/nacl/box"
    "strings"
    //"sync"
    "strconv"
)

//this code is to test the processing time of shared franking over a network. 
//this script simulates clients sending a message and then times how long it takes all the servers to complete the shared franking processing protocol

func main() {

    maxMsgLen := 1020
    msgLenIncrements := 20
    numIterations := 1000
    CTX_LEN := 32
    
    numServers:= 1
    numServersMax := 10
    serverAddrs := make([]string, numServersMax)
    
    
    if len(os.Args) < 3 {
        log.Println("clientServer1 [numServers] [serverAddr2] ... [serverAddrN]")
        return
    } else {
    	numServers, _ = strconv.Atoi(os.Args[1]) 
    	numServers = numServers - 1 //this is the first servers, so there are N - 1 others
    	if numServers > numServersMax {
    		log.Println("numServers exceeds maximum")
    	}
    	for i:=0; i < numServers; i++ {
    		serverAddrs[i] = os.Args[i+2]
    	}
    }
    
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    //using a deterministic source of randomness for testing 
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers/auditors should be known 
    //ahead of time and those would be used
    _, clientSecretKey, err := box.GenerateKey(strings.NewReader(strings.Repeat("w",10000)))
    if err != nil {
        log.Println(err)
        return
    }    
    sPublicKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("s",10000)))
    if err != nil {
        log.Println(err)
        return
    }
    
    modKey := make([]byte, 32)
    _,err =rand.Read(modKey)
    if err != nil {
    	log.Println("moderator keygen issue: ")
    }
    
    userKey := make([]byte, 16)
    _,err =rand.Read(userKey)
    if err != nil {
    	log.Println("user keygen issue: ")
    }
    
    
    //set up connections to all the servers
    conns := make([]net.Conn, numServers)
    for i:=0; i < numServers; i++ {
    	conns[i], err = tls.Dial("tcp", serverAddrs[i], conf)
    	if err != nil {
        	log.Println(err)
        	return
    	}
    	conns[i].SetDeadline(time.Time{})
    	defer conns[i].Close()
    }
    
    //data structures we'll need
    ciphertexts := make([][]byte, numServers)
    hashes := make([]byte, 32*numServers)
    
    log.Printf("msgLen, mean_processing_time, numServers=%d\n", numServers+1)
    
	for msgLen := msgLenIncrements; msgLen <= maxMsgLen; msgLen += msgLenIncrements {
		var totalTime time.Duration
		
		
		serverOutputSize := 12 + (msgLen+16+32) + 16 + 32 + (32 + CTX_LEN + 32);
		serverOutputs := make([][]byte, numServers+1)
		for i := 0; i <= numServers; i++ {
			serverOutputs[i] = make([]byte, serverOutputSize)
		}

		
		msg := make([]byte, msgLen)
		for i := 0; i < msgLen; i++ {
			msg[i] = 'a'
		}
		
		ctx := make([]byte, CTX_LEN)
		for i := 0; i < CTX_LEN; i++ {
			ctx[i] = 'c'
		}
	
		for i:= 0; i < numIterations; i++ {

			//have the client prepare request
			var writeRequestVector *C.uchar
			writeRequestLen := int(C.send((*C.uchar)(&userKey[0]), (*C.uchar)(&msg[0]), C.int(msgLen), C.int(numServers), &writeRequestVector))
			writeRequests := C.GoBytes(unsafe.Pointer(writeRequestVector), C.int(writeRequestLen))
			seedStartingPoint := writeRequestLen - numServers * 16
		
			//encrypt the requests for all the servers
			
			for i:= 0; i < numServers; i++ {
			
			    var nonce [24]byte
				//fill nonce with randomness
				_, err = rand.Read(nonce[:])
				if err != nil{
					log.Println("couldn't get randomness for nonce!")
				}
				ciphertexts[i] = box.Seal(nonce[:], writeRequests[seedStartingPoint + i * 16:seedStartingPoint + (i+1) * 16], &nonce, sPublicKey, clientSecretKey)
				
			}
		
			//start timer
			startTime := time.Now()
			
			//moderator sends requests to other servers
			for i:=0; i < numServers; i++ {
				//send data
				n, err := conns[i].Write(ciphertexts[i])
				if err != nil {
					log.Println(n, err)
					return
				}
				//log.Printf("i: %d, n: %d\n", i, n)
			}
			
			//log.Println("wrote all messages to other servers")
		
			//moderator awaits responses
			//doing this sequentially per connection
			//could speed up by using a thread per connection so they don't have to come back in order
			for i:=0; i < numServers; i++ {
		  	  count := 0
				//read hash
				for count < 32 {
				    n, err:= conns[i].Read(hashes[32*i+count:])
				    count += n
				    if err != nil && count != 32{
				        log.Println(err)
				        log.Println(n)
				    }
				}
			}
			log.Printf("hash: %x",hashes)
			
			//moderator does processing
			ctShareLen := 12 + (msgLen+16+32) + 16 + 32;

			modSeed := writeRequests[seedStartingPoint - 16: seedStartingPoint]
			res := C.mod_process(C.int(numServers), (*C.uchar)(&modKey[0]), writeRequestVector, C.int(ctShareLen), (*C.uchar)(&modSeed[0]), (*C.uchar)(&ctx[0]), (*C.uchar)(&hashes[0]), (*C.uchar)(&serverOutputs[0][0]))
			if res != 1 {
				log.Println("something went wrong in moderator processing!")
			}
			
			elapsedTime := time.Since(startTime)
			totalTime += elapsedTime
		
			//skipping the read/verify part because that's not part of this portion of the evaluation
			
			//log.Printf("iteration %d completed\n", i)
				
		}
		log.Printf("%d, %s\n", msgLen, totalTime/time.Duration(numIterations))
	}
    
    
}

func byteToInt(myBytes []byte) (x int) {
    x = int(myBytes[3]) << 24 + int(myBytes[2]) << 16 + int(myBytes[1]) << 8 + int(myBytes[0])
    return
}

func intToByte(myInt int) (retBytes []byte){
    retBytes = make([]byte, 4)
    retBytes[3] = byte((myInt >> 24) & 0xff)
    retBytes[2] = byte((myInt >> 16) & 0xff)
    retBytes[1] = byte((myInt >> 8) & 0xff)
    retBytes[0] = byte(myInt & 0xff)
    return
}
