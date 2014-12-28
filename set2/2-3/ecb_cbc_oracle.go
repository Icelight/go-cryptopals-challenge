package main

import ( 
    "fmt"
    "flag"
    "errors"
    "io/ioutil"
    "crypto/rand"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

type candidateInfo struct {
    candidateLine []byte
    hasDupes bool
    numDupes int
}

func CheckLine(line []byte, keysize int) (candidateInfo, error) {

    if keysize > len(line) || len(line) % keysize != 0 {
        err := errors.New("Keysize must be ≤ line length and line length must be a multiple of keysize")
        return candidateInfo { hasDupes: false }, err
    }

    blockMap := make(map[string]int)
    totalDupes := 0

    for i := 0; i < len(line); i += keysize {

        block := line[i:i+keysize]

        fmt.Println("checking", block)

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

func EncryptionOracle(plaintext []byte) ([]byte, string) {
    options := make([]byte, 3) //[0] - EBC or CBC, [1] - Front padding amount, [2] - Back padding amount
    _, err := rand.Read(options)

    if err != nil { panic(err) }

    frontPad, backPad := GetPaddingArrays(options[1] % 5 + 5, options[2] % 5 + 5)

    paddedPlaintext := append(frontPad, plaintext...)
    paddedPlaintext = append(paddedPlaintext, backPad...)

    var ciphertext []byte
    var algUsed string
    key, err := GenerateAESKey()

    if err != nil { panic(err) }

    if options[0] % 2 == 0 { //CBC
        iv := make([]byte, 16)
        _, err := rand.Read(iv)

        if err != nil { panic(err) }

        ciphertext, err = cryptolib.EncryptCBC(paddedPlaintext, iv, key)
        algUsed = "cbc"

        if err != nil { panic(err) }
    } else { //EBC
        ciphertext, err = cryptolib.EncryptECB(paddedPlaintext, key, true)
        algUsed = "ecb"

        if err != nil { panic(err) }
    }

    return ciphertext, algUsed
}

func GetPaddingArrays(frontLength, backLength byte) ([]byte, []byte) {
    frontPad := make([]byte, frontLength)
    backPad := make([]byte, backLength)

    _, err := rand.Read(frontPad)
    if err != nil { panic(err) }
    _, err = rand.Read(backPad)
    if err != nil { panic(err) }

    return frontPad, backPad
}

func GenerateAESKey() ([]byte, error) {
    key := make([]byte, 16)

    _, err := rand.Read(key)

    if err != nil { panic(err) }

    return key, nil
}

func main() {
    infilePtr := flag.String("in", "../files/2-3.txt", "Filename of file containing plaintext")
    flag.Parse()

    plaintext, err := ioutil.ReadFile(*infilePtr)

    if err != nil { panic(err) }

    ciphertext, algUsed := EncryptionOracle(plaintext)

    fmt.Println("Used algorithm:", algUsed)

    fmt.Println("...guessing algorithm used...")

    ecbCheck, err := CheckLine(ciphertext, 16)

    if err != nil { panic(err) }

    if ecbCheck.hasDupes {
        fmt.Println("\tGuessing ECB!")
    } else {
        fmt.Println("\tGuessing CBC!")
    }
    
}
