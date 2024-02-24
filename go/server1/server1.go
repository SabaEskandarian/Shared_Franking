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
    //"unsafe"
    //"io"
    "crypto/rand"
    "golang.org/x/crypto/nacl/box"
    //"strings"
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
    
    numServers:= 1
    numServersMax := 10
    serverAddrs := make([]string, numServersMax)

	var err error
	port := ":"
    
    if len(os.Args) < 4 {
        log.Println("server1 [numServers] [server1Port] [serverAddr2] ... [serverAddrN]")
        return
    } else {
    	numServers, _ = strconv.Atoi(os.Args[1]) 
    	numServers = numServers - 1 //this is the first servers, so there are N - 1 others
    	port += os.Args[2]
    	if numServers > numServersMax {
    		log.Println("numServers exceeds maximum")
    	}
    	for i:=0; i < numServers; i++ {
    		serverAddrs[i] = os.Args[i+3]
    	}
    }
    
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }

	modKey := make([]byte, 32)
    _,err =rand.Read(modKey)
    if err != nil {
    	log.Println("moderator keygen issue: ")
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
    
    //set up first server
    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }
    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    ln, err := tls.Listen("tcp", port, config)  
    if err != nil {
        log.Println(err)
        return
    }
    defer ln.Close()

    //data structures we'll need
    hashes := make([]byte, 32*numServers)

	log.Printf("server side processing time")
	log.Printf("msgLen, mean_processing_time, numServers=%d\n", numServers+1)

    
	for msgLen := msgLenIncrements; msgLen <= maxMsgLen; msgLen += msgLenIncrements {
		var totalTime time.Duration
		
		serverOutputSize := 12 + (msgLen+16+32) + 16 + 32 + (32 + CTX_LEN + 32);
		s1Output := make([]byte, serverOutputSize)
		
		ctx := make([]byte, CTX_LEN)
		for i := 0; i < CTX_LEN; i++ {
			ctx[i] = 'c'
		}
	
		for i:= 0; i < numIterations; i++ {
		
		    //start connection from client
			clientConn, err := ln.Accept()
			if err != nil {
				log.Println(err)
			}
			clientConn.SetDeadline(time.Time{})

			writeRequestLenBytes := make([]byte, 4)

			//read the write request length (not the same as the total bytes sent by client)
			count := 0
			for count < 4 {
				n, err:= clientConn.Read(writeRequestLenBytes[count:])
				count += n
				if err != nil && count != 4{
					log.Println(err)
					log.Println(n)
				}
			}
			writeRequestLen := byteToInt(writeRequestLenBytes)

			seedStartingPoint := writeRequestLen - numServers * 16
			clientRequestLen := writeRequestLen + (24+box.Overhead)*(numServers-1)
			clientRequest := make([]byte, clientRequestLen)

			count = 0
			for count < clientRequestLen {
				n, err:= clientConn.Read(clientRequest[count:])
				count += n
				if err != nil && count != 32{
					log.Println(err)
					log.Println(n)
				}
			}

			ctLen := 24+16+box.Overhead
			s1Share := clientRequest[:seedStartingPoint]
			
			//start timer
			startTime := time.Now()

			//moderator sends requests to other servers
			for i:=0; i < numServers; i++ {
				//send data
				n, err := conns[i].Write(clientRequest[seedStartingPoint+i*ctLen:seedStartingPoint+(i+1)*ctLen])
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
			//log.Printf("hash: %x",hashes)
			
			//moderator does processing
			ctShareLen := 12 + (msgLen+16+32) + 16 + 32;

			modSeed := clientRequest[seedStartingPoint - 16: seedStartingPoint]
			res := C.mod_process(C.int(numServers), (*C.uchar)(&modKey[0]), (*C.uchar)(&s1Share[0]), C.int(ctShareLen), (*C.uchar)(&modSeed[0]), (*C.uchar)(&ctx[0]), (*C.uchar)(&hashes[0]), (*C.uchar)(&s1Output[0]))
			if res != 1 {
				log.Println("something went wrong in moderator processing!")
			}

			//stop timer. server side processing is done. The rest is client message retrieval stuff.
			elapsedTime := time.Since(startTime)
			totalTime += elapsedTime

			otherServerOutputSize := 12 + (msgLen+16+32) + 16 + 32 + (32 + CTX_LEN + 32)
			otherServerCtSize := otherServerOutputSize + 24 + box.Overhead
			otherServerCts := make([]byte, otherServerCtSize*numServers)
		
			//read the message shares from the other servers
			for i:=0; i < numServers; i++ {
		  	  count := 0
				//read message share
				for count < otherServerCtSize {
				    n, err:= conns[i].Read(otherServerCts[otherServerCtSize*i+count:otherServerCtSize*(i+1)])
				    count += n
				    if err != nil && count != otherServerCtSize{
				        log.Println(err)
				        log.Println(n)
				    }
				}
			}

			//send shares back to the client
			n, err := clientConn.Write(s1Output)
			if err != nil {
				log.Println(n, err)
				return
			}
			n, err = clientConn.Write(otherServerCts)
			if err != nil {
				log.Println(n, err)
				return
			}

			clientConn.Close()
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
