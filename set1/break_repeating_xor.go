package main

import (
    "io/ioutil"
    "encoding/base64"
    "errors"
    "flag"
    "fmt"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

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
            dist, err := cryptolib.CalculateHammingDistance(firstBlock, secondBlock)

            if err != nil { panic (err) }

            fltDist := float32(dist) / float32(i) //Normalize computed distance to keysize

            avgDist += float32(fltDist)
            numIters++
        }

        avgDist /= float32(numIters) 

        if avgDist < bestDist {
            bestDist = avgDist
            bestKeysize = i
        }

        fmt.Println("Num iters for keysize of", i, "was: ~~", numIters, "~~", "\n\tDistance is:", avgDist)
    }

    return bestKeysize, nil
}

func transposeBlocks(blocks []byte, keysize int) [][]byte {

    keyBlocks := make([][]byte, keysize)

    for i, _ := range keyBlocks {

        keyBlocks[i] = make([]byte, len(blocks) / keysize)

        for j := 0; j < len(keyBlocks[i]); j++ {
            keyBlocks[i][j] = blocks[i + (keysize * j)]
        }
    }

    return keyBlocks
}

func expandKey(key []byte, length int) []byte {

    expandedKey := make([]byte, length)

    for i := range expandedKey {
        expandedKey[i] = key[i % len(key)]
    }

    return expandedKey
}

func generatePlaintext(rawBytes, key []byte) []byte {

    plaintext := make([]byte, len(rawBytes))

    for i, _ := range plaintext {
        plaintext[i] = rawBytes[i] ^ key[i]
    }

    return plaintext
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

    //Now let's reformat our blocks such that the first block contains the first byte of every keysize
    //length block in the original, the second block contains the second byte of every keysize length block
    //in the original, etc.
    keyBlocks := transposeBlocks(rawBytes, bestKeysize)

    //For each element i in the key, solve for keyBlocks[i]
    key := make([]byte, bestKeysize)

    for i, block := range keyBlocks {
        _, _, keyChar := cryptolib.FindBestPlaintext(block)

        key[i] = keyChar
    }

    plaintext := generatePlaintext(rawBytes, expandKey(key, len(rawBytes)))

    fmt.Println(string(plaintext))
    
}
