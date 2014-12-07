package main
/*
import (
    "fmt"
    "encoding/hex"
    "flag"
    "io/ioutil"
    "errors"
)

func RepeatingKeyXor(plainBytes, keyBytes []byte) ([]byte, error) {

    if len(keyBytes) <= 0 {
        err := errors.New("Key must have a length of at least one")
        return nil, err
    }
    
    cipherBytes := make([]byte, len(plainBytes))

    for i, char := range plainBytes {
        cipherBytes[i] = char ^ keyBytes[i % len(keyBytes)]
    }

    return cipherBytes, nil
}

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
    cipherBytes, err := RepeatingKeyXor(plainBytes[:len(plainBytes)-1], []byte(*keyPtr))

    fmt.Println(hex.EncodeToString(cipherBytes))

    err = ioutil.WriteFile(*outfilePtr, cipherBytes, 0777)

    if err != nil {
        panic(err)
    }
} */