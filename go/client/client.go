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
    //"net"
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
    numIterations := 10
    CTX_LEN := 32
    
    numServers:= 2
    numOtherServers := 1
    numServersMax := 10
    server1Addr := ""
    
    var err error

    if len(os.Args) < 3 {
        log.Println("client [numServers] [server1Addr]")
        return
    } else {
    	numServers, _ = strconv.Atoi(os.Args[1]) 
		numOtherServers = numServers - 1
    	if numServers > numServersMax {
    		log.Println("numServers exceeds maximum")
    	}
    	server1Addr = os.Args[2]
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

    userKey := make([]byte, 16)
    _,err =rand.Read(userKey)
    if err != nil {
    	log.Println("user keygen issue: ")
    }

	ctx := make([]byte, CTX_LEN)
	for i := 0; i < CTX_LEN; i++ {
		ctx[i] = 'c'
	}
    
    
    //data structures we'll need
    ciphertexts := make([][]byte, numOtherServers)
    
	log.Printf("client observed message processing time")
    log.Printf("msgLen, mean_processing_time, numServers=%d\n", numServers)
    
	for msgLen := msgLenIncrements; msgLen <= maxMsgLen; msgLen += msgLenIncrements {
		var totalTime time.Duration
		
		serverOutputSize := 12 + (msgLen+16+32) + 16 + 32 + (32 + CTX_LEN + 32);
		serverOutputs := make([][]byte, numServers)
		for i := 0; i < numServers; i++ {
			serverOutputs[i] = make([]byte, serverOutputSize)
		}
		
		msg := make([]byte, msgLen)
		for i := 0; i < msgLen; i++ {
			msg[i] = 'a'
		}

		for i:= 0; i < numIterations; i++ {

			//start timer
			startTime := time.Now()

			//have the client prepare request
			var writeRequestVector *C.uchar
			writeRequestLen := int(C.send((*C.uchar)(&userKey[0]), (*C.uchar)(&msg[0]), C.int(msgLen), C.int(numServers), &writeRequestVector))
			writeRequests := C.GoBytes(unsafe.Pointer(writeRequestVector), C.int(writeRequestLen))
			seedStartingPoint := writeRequestLen - numOtherServers * 16
		
			//encrypt the requests for all the servers
			
			for i:= 0; i < numOtherServers; i++ {
			
			    var nonce [24]byte
				//fill nonce with randomness
				_, err = rand.Read(nonce[:])
				if err != nil{
					log.Println("couldn't get randomness for nonce!")
				}
				ciphertexts[i] = box.Seal(nonce[:], writeRequests[seedStartingPoint + i * 16:seedStartingPoint + (i+1) * 16], &nonce, sPublicKey, clientSecretKey)
				
			}

			//connect to moderator server
			conn, err := tls.Dial("tcp", server1Addr, conf)
			if err != nil {
				log.Println(err)
				return
			}
			conn.SetDeadline(time.Time{})

			//send writeRequestLen to moderator
			n,err := conn.Write(intToByte(writeRequestLen))
			if err != nil {
				log.Println(n, err)
				return
			}

			//send stuff to moderator
			n,err = conn.Write(writeRequests[:seedStartingPoint])
			if err != nil {
				log.Println(n, err)
				return
			}
			for i := 0; i < numOtherServers; i++ {
				n,err = conn.Write(ciphertexts[i])
				if err != nil {
					log.Println(n, err)
					return
				}
			}

			//receive back shares of the message
			serverOutputSize := 12 + (msgLen+16+32) + 16 + 32 + (32 + CTX_LEN + 32)
			serverCtSize := serverOutputSize + 24 + box.Overhead
			shares := make([]byte, serverOutputSize * numServers)
			serverCt := make([]byte, serverCtSize)
			//first the server 1 share, then the ciphertexts of others'
			count := 0
			//read first message share
			for count < serverOutputSize {
				n, err:= conn.Read(shares[count:serverOutputSize])
				count += n
				if err != nil && count != serverOutputSize{
					log.Println(err)
					log.Println(n)
				}
			}
			//read and decrypt other server ciphertexts
			for i := 0; i < numOtherServers; i++ {
				count = 0
				for count < serverCtSize {
				    n, err:= conn.Read(serverCt[count:])
				    count += n
				    if err != nil && count != serverCtSize{
				        log.Println(err)
				        log.Println(n)
				    }
				}
				//decrypt share
				var decryptNonce [24]byte
				copy(decryptNonce[:], serverCt[:24])
				decryptedShare, ok := box.Open(nil, serverCt[24:], &decryptNonce, sPublicKey, clientSecretKey)
				copy(shares[serverOutputSize*(i+1):serverOutputSize*(i+2)], decryptedShare)
				if !ok {
					log.Println("Decryption not ok!!")
					log.Printf("decryption nonce: %x\\", decryptNonce)
				}
			}

			//read message
			recoveredMsg := make([]byte, msgLen)
			recoveredR := make([]byte, 16)
			recoveredC2_1 := make([]byte, 32)
			recoveredSigma := make([]byte, 32)
			recoveredFo := make([]byte, 32)
			recoveredCtx := make([]byte, CTX_LEN)
			_ = int(C.read((*C.uchar)(&userKey[0]), C.int(numServers), (*C.uchar)(&shares[0]), C.int(serverOutputSize), (*C.uchar)(&recoveredMsg[0]), (*C.uchar)(&recoveredR[0]), (*C.uchar)(&recoveredC2_1[0]), (*C.uchar)(&recoveredCtx[0]), (*C.uchar)(&recoveredSigma[0]), (*C.uchar)(&recoveredFo[0])))

			conn.Close()
			
			elapsedTime := time.Since(startTime)
			totalTime += elapsedTime

			//check we read the right message and context
			for i:=0; i < msgLen; i++ {
				if msg[i] != recoveredMsg[i] {
					log.Println("decryption got wrong message!")
				}
			}
			for i:=0; i < CTX_LEN; i++ {
				if ctx[i] != recoveredCtx[i] {
					log.Println("read wrong context!")
				}
			}

			//TODO verify?

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
