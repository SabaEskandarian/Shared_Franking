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
    "time"
    "os"
    //"unsafe"
    "io"
    "golang.org/x/crypto/nacl/box"
    "strings"
)

func main() {

    maxMsgLen := 1020
    msgLenIncrements := 20
    numIterations := 1000
    CTX_LEN := 32

    port := ":"

    if len(os.Args) < 2 {
        log.Println("otherServers [port]")
        return
    } else {
    	port += os.Args[1]
    }

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
    
    
    //using a deterministic source of randomness for testing
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers should be known 
    //ahead of time and those would be used
    clientPublicKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("w",10000)))
    if err != nil {
        log.Println(err)
        return
    }    
    _, secretKey, err := box.GenerateKey(strings.NewReader(strings.Repeat("s",10000)))
    if err != nil {
        log.Println(err)
        return
    }
    
    conn, err := ln.Accept()
    if err != nil {
    	log.Println(err)
    }
    conn.SetDeadline(time.Time{})
    defer conn.Close()
    
    for msgLen := msgLenIncrements; msgLen <= maxMsgLen; msgLen += msgLenIncrements {
    	for i:= 0; i < numIterations; i++ {

            //read the message from the first server

		    clientInput := make([]byte, 24+16+box.Overhead)
		    for count := 0; count < 24+16+box.Overhead; {
		        n, err:= conn.Read(clientInput[count:])
		        count += n
		        if err != nil && err != io.EOF && count != 24+16+box.Overhead {
		            log.Println(err)
		        }
		    }
		    
		    //log.Println("got data")
            
            //decrypt the message
		    var decryptNonce [24]byte
		    copy(decryptNonce[:], clientInput[:24])
		    decryptedQuery, ok := box.Open(nil, clientInput[24:], &decryptNonce, clientPublicKey, secretKey)
		    if !ok {
		        log.Println("Decryption not ok!!")
		        log.Printf("decryption nonce: %x\\", decryptNonce)
		    }
            
            hash := make([]byte, 32)
            serverOutputSize := 12 + (msgLen+16+32) + 16 + 32 + (32 + CTX_LEN + 32)
            
            outputShare := make([]byte, serverOutputSize)
            
            //process the message
            ctShareLen := 12 + (msgLen+16+32) + 16 + 32
			res := C.process((*C.uchar)(&decryptedQuery[0]), C.int(ctShareLen), (*C.uchar)(&hash[0]), (*C.uchar)(&outputShare[0]))
			if res != 1 {
				log.Println("something went wrong in processing")
			}
			
			//log.Printf("hash: %x; len = %d", hash, len(hash))
            
            //write back w_i' (shared franking)
            _,err := conn.Write(hash)
            if err != nil {
            	log.Println(err)
            }
            
            //log.Println("wrote back\n")
            
            //NOTE: from here on is not the timed part, so not including for this test
            //write back the output share
            //_,err = conn.Write(outputShare)
            //if err != nil {
            //	log.Println(err)
            //}
    	}
    }
    
}

func byteToInt(myBytes []byte) (x int) {
    x = int(myBytes[3]) << 24 + int(myBytes[2]) << 16 + int(myBytes[1]) << 8 + int(myBytes[0])
    return
}
