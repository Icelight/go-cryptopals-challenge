package main

import (
    "fmt"
    "encoding/hex"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)


func main() {
    hexString := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    hexBytes, err := hex.DecodeString(hexString)

    if err != nil { panic(err) }

    plaintext, bestScore, char := cryptolib.FindBestPlaintext(hexBytes)

    fmt.Println("Best plaintext is:", plaintext, ", with score:", bestScore, "using char:", string(char))
}
