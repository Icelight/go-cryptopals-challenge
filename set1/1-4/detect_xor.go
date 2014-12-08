package main

import (
    "os"
    "fmt"
    "flag"    
    "bufio"
    "encoding/hex"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

func main() {

    filenamePtr := flag.String("filename", "../files/1-4.txt", "Filename of crypto file")
    flag.Parse()

    file, err := os.Open(*filenamePtr)
    defer file.Close()

    if err != nil {
        panic(err)
    }

    scanner := bufio.NewScanner(file)

    bestScore := float32(0)
    bestPlaintext := ""

    for scanner.Scan() {
        hexBytes, err := hex.DecodeString(scanner.Text())

        if err != nil { panic(err) }

        plaintext, _, _ := cryptolib.FindBestPlaintext(hexBytes)
        score := cryptolib.ScorePlaintext([]byte(plaintext))

        if score > bestScore {
            bestScore = score
            bestPlaintext = plaintext
        }
    }

    fmt.Println("Best plaintext found:", bestPlaintext)
}
