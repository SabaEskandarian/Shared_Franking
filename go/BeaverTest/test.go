package main

import (

    "log"
    "crypto/rand"
    "time"
    "bytes"
)

func main() {

    log.Println("test")

    numIterations := 1000000
    var totalTime time.Duration

    for i:=0; i < numIterations; i++ {

        //set up the Beaver triple
        A1Bytes := make([]byte, 16)
        A2Bytes := make([]byte, 16)
        B1Bytes := make([]byte, 16)
        B2Bytes := make([]byte, 16)
        C1Bytes := make([]byte, 16)

        var eltA1, eltA2, eltB1, eltB2, eltC1, eltC2, eltA, eltB, eltC Element

        _, err := rand.Read(A1Bytes)
        if err != nil {
            panic(err)
        }
        _, err = rand.Read(A2Bytes)
        if err != nil {
            panic(err)
        }
        _, err = rand.Read(B1Bytes)
        if err != nil {
            panic(err)
        }
        _, err = rand.Read(B2Bytes)
        if err != nil {
            panic(err)
        }
        _, err = rand.Read(C1Bytes)
        if err != nil {
            panic(err)
        }

        eltA1.SetBytes(A1Bytes)
        eltA2.SetBytes(A2Bytes)
        eltB1.SetBytes(B1Bytes)
        eltB2.SetBytes(B2Bytes)
        eltC1.SetBytes(C1Bytes)

        eltA.Add(&eltA1, &eltA2)
        eltB.Add(&eltB1, &eltB2)
        eltC.Mul(&eltA, &eltB)
        eltC2.Sub(&eltC, &eltC1)

        //C2Bytes := eltC2.Bytes()

        //set up random input shares to multiply
        x1Bytes := make([]byte, 16)
        x2Bytes := make([]byte, 16)
        y1Bytes := make([]byte, 16)
        y2Bytes := make([]byte, 16)
        _, err = rand.Read(x1Bytes)
        if err != nil {
            panic(err)
        }
        _, err = rand.Read(x2Bytes)
        if err != nil {
            panic(err)
        }
        _, err = rand.Read(y1Bytes)
        if err != nil {
            panic(err)
        }
        _, err = rand.Read(y2Bytes)
        if err != nil {
            panic(err)
        }

        var eltx1, eltx2, elty1, elty2, eltx, elty Element
        var eltE, eltD, eltE1, eltE2, eltD1,eltD2 Element
        var tempx, tempy, eltz1, eltz2, eltz Element

        //timing work for one server only
        //start timer
        startTime := time.Now()

        eltx1.SetBytes(x1Bytes)
        elty1.SetBytes(y1Bytes)

        eltE1.Sub(&eltx1, &eltA1)
        eltD1.Sub(&elty1, &eltB1)

        eltx2.SetBytes(x2Bytes)
        elty2.SetBytes(y2Bytes)

        E1Bytes := eltE1.Bytes()
        D1Bytes := eltD1.Bytes()

        //pause time
        elapsedTime := time.Since(startTime)
        totalTime += elapsedTime

        eltE2.Sub(&eltx2, &eltA2)
        eltD2.Sub(&elty2, &eltB2)

        E2Bytes := eltE2.Bytes()
        D2Bytes := eltD2.Bytes()

        eltE1.SetBytes(E1Bytes)
        eltD1.SetBytes(D1Bytes)

        //resume timer
        startTime = time.Now()

        eltE2.SetBytes(E2Bytes)
        eltD2.SetBytes(D2Bytes)

        eltE.Add(&eltE1, &eltE2)
        eltD.Add(&eltD1, &eltD2)

        tempx.Mul(&eltx1, &eltD)
        tempy.Mul(&elty1, &eltE)

        eltz1.Add(&eltC1, &tempx)
        eltz1.Add(&eltz1, &tempy)

        tempx.Mul(&eltE, &eltD)
        eltz1.Sub(&eltz1, &tempx)

        z1Bytes := eltz1.Bytes()
        _ = z1Bytes

        //end timer
        elapsedTime = time.Since(startTime)
        totalTime += elapsedTime

        //finish other server work and check
        tempx.Mul(&eltx2, &eltD)
        tempy.Mul(&elty2, &eltE)
        eltz2.Add(&eltC2, &tempx)
        eltz2.Add(&eltz2, &tempy)

        eltz.Add(&eltz1, &eltz2)
        eltx.Add(&eltx1, &eltx2)
        elty.Add(&elty1, &elty2)
        var check Element
        check.Mul(&eltx, &elty)

        zBytes := eltz.Bytes()
        checkBytes := check.Bytes()

        if bytes.Compare(zBytes, checkBytes) != 0 {
            log.Println("incorrect result")
            log.Printf("Z computed: %x", zBytes)
            log.Printf("Z check: %x", checkBytes)
        }
    }

		log.Printf("Time for %d Beaver multiplications: %s\n", numIterations, totalTime)

}
