package main

import (
    "fmt"
    "os"
    "errors"
    "flag"
    "bufio"
    "encoding/hex"
)

type candidateInfo struct {
    candidateLine []byte
    hasDupes bool
    numDupes int
}

func checkLine(line []byte, keysize int) (candidateInfo, error) {

    if keysize > len(line) || len(line) % keysize != 0 {
        err := errors.New("Keysize must be ≤ line length and line length must be a multiple of keysize")
        return candidateInfo { hasDupes: false }, err
    }

    blockMap := make(map[string]int)
    totalDupes := 0

    for i := 0; i < len(line); i += keysize {

        block := line[i:i+keysize]

        _, ok := blockMap[string(block)]

        if ok {
            totalDupes++
        } else {
            blockMap[string(block)] = 1
        }

    }

    info := candidateInfo { candidateLine: line, numDupes: totalDupes }

    if totalDupes > 0 {
        info.hasDupes = true
    } 

    return info,  nil
}

func main() {
	infilePtr := flag.String("in", "../files/1-8.dat", "Filename containing hex-encoded ciphertexts. One per line")
    keysize := flag.Int("keysize", 16, "Size of the key that was used to encrypt one of the lines in the infile")
	flag.Parse()

	file, err := os.Open(*infilePtr)
    defer file.Close()

    if err != nil { panic(err) }

    scanner := bufio.NewScanner(file)
    candidates := make([]candidateInfo, 0)

    for scanner.Scan() {
        rawBytes, err := hex.DecodeString(scanner.Text())

        if err != nil { panic(err) }

        candidate, err := checkLine(rawBytes, *keysize)

        if err != nil { panic(err) }

        candidates = append(candidates, candidate)
    }

    fmt.Println("Detected lines potentially encrypted with AES-ECB:")

    for _, candidate := range candidates {
        if candidate.hasDupes {
            fmt.Println(hex.EncodeToString(candidate.candidateLine))
        }
    }
}
