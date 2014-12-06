package main

import (
    "os"
    "fmt"
    "flag"    
    "bufio"
)



func main() {

    filenamePtr := flag.String("filename", "1-4.txt", "Filename of crypto file")
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
        plaintext, _, _ := FindBestPlaintext(scanner.Text())
        score := ScorePlaintext(plaintext)

        if score > bestScore {
            bestScore = score
            bestPlaintext = plaintext
        }
    }

    fmt.Println("Best plaintext found:", bestPlaintext)
}
