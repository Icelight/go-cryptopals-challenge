package main

import (
    "fmt"
    "flag"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

func main() {
    text := flag.String("text", "YELLOW SUBMARINE", "The text to pad.")
    flag.Parse()

    output := cryptolib.Pkcs7Padding([]byte(*text))

    fmt.Println("Output:", output)
}
