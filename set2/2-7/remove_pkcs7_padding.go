package main

import (
    "fmt"
    "flag"
    "encoding/hex"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

func main() {
    text := flag.String("text", "31323334353637383930060606060606", "The hex-encoded padded plaintext.")
    flag.Parse()

    hexBytes, err := hex.DecodeString(*text)

    trimmedText, err := cryptolib.RemovePkcs7Padding(hexBytes)

    if err != nil { panic(err) }

    fmt.Println("Trimmed plaintext is:", string(trimmedText))
}
