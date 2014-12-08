package main

import (
    "fmt"
    "encoding/hex"
    "flag"
    "io/ioutil"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

func main() {

    infilePtr := flag.String("in", "../files/1-5.txt", "Filename of plaintext file to encrypt")
    outfilePtr := flag.String("out", "cipher.dat", "Filename of encrypted file")
    keyPtr := flag.String("key", "ICE", "Key to use when encrypting plaintext")
    flag.Parse()

    plainBytes, err := ioutil.ReadFile(*infilePtr)

    if err != nil {
        panic(err)
    }

    //We're reading from a file, and writing back, so skip the EOF character
    cipherBytes, err := cryptolib.RepeatingKeyXor(plainBytes[:len(plainBytes)-1], []byte(*keyPtr))

    fmt.Println(hex.EncodeToString(cipherBytes))

    err = ioutil.WriteFile(*outfilePtr, cipherBytes, 0777)

    if err != nil {
        panic(err)
    }
} 