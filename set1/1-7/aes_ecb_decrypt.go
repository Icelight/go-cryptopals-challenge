package main

import (
    "fmt"
    "flag"
    "io/ioutil"
    "encoding/base64"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

func main() {
    infilePtr := flag.String("in", "../files/1-7.dat", "Filename of file containing base64'd AES ECB encrypted contents")
    keyPtr := flag.String("key", "YELLOW SUBMARINE", "Decryption key")
    flag.Parse()

    base64Bytes, err := ioutil.ReadFile(*infilePtr)

    if err != nil { panic(err) }

    ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(base64Bytes)))
    base64.StdEncoding.Decode(ciphertext, base64Bytes)

    key := []byte(*keyPtr)

    plaintext, err := cryptolib.DecryptECB(ciphertext, key)

    if err != nil { panic(err) }

    fmt.Println(string(plaintext))
}