package main

import (
    "fmt"
    "flag"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

func main() {
    text := flag.String("text", "YELLOW SUBMARINE", "The text to pad.")
    length := flag.Int("length", 20, "The desired length.")
    flag.Parse()

    output := cryptolib.Pkcs7Padding([]byte(*text), *length)

    fmt.Println("Output:", output)
}
