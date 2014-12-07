package main

import (
    "io/ioutil"
    "encoding/base64"
    "errors"
    "flag"
    "fmt"
)

func CalculateHammingDistance(first []byte, second []byte) (int, error) {

    if len(first) != len(second) {
        err := errors.New("Input byte arrays must be of the same length")
        return -1, err
    }

    distance := 0
    xor := make([]byte, len(first))

    for i, _ := range first {
        xor[i] = first[i] ^ second[i]
    }

    for _, val := range xor {
        for val > 0 {
            distance++
            val &= val - 1
        }
    }

    return distance, nil
}

func getKeysizeBlocks(input []byte, offset, keysize int) ([]byte, []byte) {

    return input[offset:offset+keysize], input[offset+keysize:offset+keysize+keysize]
}

func FindBestKeysize(input []byte, minsize, maxsize int) (int, error) {
    
    if minsize > maxsize {
        err := errors.New("Maximum key size must be at least as large as the minimum key size")
        return -1, err
    }

    //Twice our keysize can't be larger than our input size as we take two keysize blocks from the input
    if maxsize > (len(input) / 2) {
        maxsize = (len(input) / 2)
    }

    bestDist := float32(1000000)
    bestKeysize := 0

    for i := minsize; i <= maxsize; i++ {

        avgDist := float32(0)
        numIters := 0

        for offset := 0; offset + i + i < len(input); offset += i {

            firstBlock, secondBlock := getKeysizeBlocks(input, offset, i)
            dist, err := CalculateHammingDistance(firstBlock, secondBlock)
            dist /= i //Normalize computed distance to keysize

            if err != nil { panic (err) }

            avgDist += float32(dist)
            numIters++
        }

        avgDist /= float32(numIters) 

        if avgDist < bestDist {
            bestDist = avgDist
            bestKeysize = i
        }

        fmt.Println("Num iters for keysize of", i, "was: ~~", numIters, "~~", "\n\tDistance is:", bestDist)
    }

    return bestKeysize, nil
}


func main() {

    infilePtr := flag.String("in", "../files/1-6.dat", "Filename of file containing encrypted text that has been base64'd")
    keysizeMin := flag.Int("keymin", 2, "Minimum key size to test against")
    keysizeMax := flag.Int("keymax", 40, "Maximum key size to test against")
    flag.Parse()

    base64Bytes, err := ioutil.ReadFile(*infilePtr)

    if err != nil {
        panic(err)
    }

    rawBytes := make([]byte, base64.StdEncoding.DecodedLen(len(base64Bytes)))
    base64.StdEncoding.Decode(rawBytes, base64Bytes)

    bestKeysize, err := FindBestKeysize(rawBytes, *keysizeMin, *keysizeMax)

    if err != nil { panic(err) }

    fmt.Println("Best keysize found was:", bestKeysize)
}
