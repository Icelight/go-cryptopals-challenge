package main

import (
    "fmt"
    "flag"
    "bytes"
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

    ciphertext, err := cryptolib.EncryptECB(fulltext, key, true)
    
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
        known[i] = 'A'
    }

    ciphertext := EncryptionOracle(known)

    isEcb, err := cryptolib.IsECB(ciphertext, blockSize)
    if err != nil { panic(err) }

    return isEcb
}

func ByteAtATimeDecrypt(blockSize int) []byte {

    //First let's determine how many unknown blocks we have and the total length of the secret
    ciphertext := EncryptionOracle([]byte(""))
    secretLength := len(ciphertext)
    numBlocks := secretLength / blockSize

    knownChars := make([]byte, 0)

    //For each block in the secret text, determine what each byte must be
    for currBlock := 1; currBlock <= numBlocks; currBlock++ { //Starting from 1 so we can ignore our known block which is at the front

        //Iterate over each byte in the current block and figure out what that byte is.
        for currByte := 0; currByte < blockSize; currByte++ {

            //Build up our known block for this round and get the round ciphertext containing shortBlock || secret
            //Essentially, our control will contain:
            //  [SHORT][KNOWN][c][Actual Ciphertext we don't care about]
            //And our round:
            //  [SHORT][Actual Ciphertext that we already know (same length as KNOWN!)][?]
            //Thus we can always check against [?] with [c] 
            shortBlock := make([]byte, (currBlock * blockSize) - len(knownChars) - 1)
            for i, _ := range shortBlock {
                shortBlock[i] = 'A'
            }

            roundCiphertext := EncryptionOracle(shortBlock)[0:currBlock*blockSize]

            //Now build up a ciphertext with a known control value until we find one matching our round ciphertext
            //Starting at char 10 to cover newlines
            for character := byte(10); character < 127; character++ {
                control := make([]byte, 0)
                control = append(control, shortBlock...)
                control = append(control, knownChars...)
                control = append(control, character)

                controlCiphertext := EncryptionOracle(control)[0:currBlock*blockSize]

                if bytes.Equal(roundCiphertext, controlCiphertext) {
                    knownChars = append(knownChars, character)
                    break;
                }
            }
        }
    }

    return knownChars
}

func main() {
    infilePtr := flag.String("in", "../files/2-4.dat", "Filename of file containing a base64'd string for use by enc. oracle")
    flag.Parse()

    base64Bytes, err := ioutil.ReadFile(*infilePtr)
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

    plaintext := ByteAtATimeDecrypt(blockSize)

    fmt.Println("Plaintext is:\n")
    fmt.Println(string(plaintext))
}
