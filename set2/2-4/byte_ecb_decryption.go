package main

import (
    "fmt"
    "flag"
    "io/ioutil"
    "crypto/rand"
    "encoding/base64"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

var aesKey []byte

var rawBytes []byte

func EncryptionOracle(plaintext []byte) []byte {

    key, err := GenerateAESKey()

    if err != nil { panic(err) }

    var fulltext []byte
    fulltext = append(fulltext, plaintext...)
    fulltext = append(fulltext, rawBytes...)

    ciphertext, err := cryptolib.EncryptECB(fulltext, key)
    
    return ciphertext
}

func GenerateAESKey() ([]byte, error) {
    if aesKey != nil {
        return aesKey, nil
    }

    aesKey = make([]byte, 16)

    _, err := rand.Read(aesKey)

    if err != nil { panic(err) }

    return aesKey, nil
}

func DetermineBlockSize() int {
    var test []byte
    length := len(EncryptionOracle(nil))

    for i := 0; i < 130; i++ {
        test = append(test, byte('A'))

        newLength := len(EncryptionOracle(test))

        if length != newLength {
            return newLength - length
        }
    }

    return 0
}

func IsECB(blockSize int) bool {

    known := make([]byte, blockSize * 3)

    //Build up three blocks worth of repeating character known plaintext
    for i, _ := range known {
        known[i] = byte('A')
    }

    ciphertext := EncryptionOracle(known)

    isEcb, err := cryptolib.IsECB(ciphertext, blockSize)
    if err != nil { panic(err) }

    return isEcb
}

func main() {
    unknownFilePtr := flag.String("extra", "../files/2-4.dat", "Filename of file containing an unknown base64'd string")
    flag.Parse()

    base64Bytes, err := ioutil.ReadFile(*unknownFilePtr)
    if err != nil { panic(err) }

    rawBytes = make([]byte, base64.StdEncoding.DecodedLen(len(base64Bytes)))
    base64.StdEncoding.Decode(rawBytes, base64Bytes)

    //First determine the block size
    blockSize := DetermineBlockSize()
    if blockSize == 0 { panic("Could not determine block size") }
    fmt.Println("Block size is:", blockSize)

    //Now make sure that this is ECB!
    isEcb := IsECB(blockSize)
    if isEcb {
        fmt.Println("Determined that the contents have been encrypted under AES-ECB!")
    } else {
        fmt.Println("Contents have not been encrypted under AES-ECB. Exiting...")
        return
    }

}
