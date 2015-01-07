package main

import (
    "fmt"
    "strconv"
    "errors"
    "crypto/rand"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

var aesKey []byte
var aesIV []byte

func GenerateAESKey() []byte {
    if aesKey != nil {
        return aesKey
    }

    aesKey = make([]byte, 16)

    _, err := rand.Read(aesKey)

    if err != nil { panic(err) }

    return aesKey
}

func GenerateAESIV() []byte {
    if aesIV != nil {
        return aesIV
    }

    aesIV = make([]byte, 16)

    _, err := rand.Read(aesIV)

    if err != nil { panic(err) }

    return aesIV
}

func ServerDecryptCheckStub(ciphertext []byte, iv []byte) bool {
    GenerateAESKey()

    plaintext, err := cryptolib.DecryptCBC(ciphertext, iv, aesKey)

    if err != nil { return false }

    validPadding := cryptolib.ValidatePkcs7Padding(plaintext)

    return validPadding

}

func CBCPaddingOracleAttack(ciphertext []byte, blocksize int) ([]byte, error) {
    numBlocks := len(ciphertext) / blocksize

    plaintext := make([]byte, len(ciphertext))

    //Break each block, starting with the last...
    for currBlock := numBlocks - 1; currBlock >= 0; currBlock-- {

        currBlockText := ciphertext[currBlock * blocksize:(currBlock + 1) * blocksize]

        var prevBlock []byte

        if currBlock == 0 {
            prevBlock = GenerateAESIV();
        } else {
            prevBlock = ciphertext[(currBlock - 1) * blocksize:currBlock*blocksize]
        }

        //Break each byte in the block, starting with the last...
        for currByte := blocksize - 1; currByte >= 0; currByte-- {

            //Looking for padding 0x01 for the last byte, 0x02 for the second last, etc.
            padValue := byte(blocksize - currByte)

            attackBlock := make([]byte, len(currBlockText))
            copy(attackBlock, currBlockText)

            //Now copy into our attack block the bytes we've already determined from
            //our previous iterations in this block such that they will turn into
            //the padding value that we expect when decrypted. Basically the same idea as the
            //CBC Bitflipping attack
            for i := blocksize - 1; i > currByte; i-- {
                attackBlock[i] ^= plaintext[(currBlock * blocksize) + i] ^ padValue
            }

            correct := false

            //Now let's check all possible values for the current byte until we get a valid padding.
            for testByte := 0; testByte < 256; testByte++ {
                attackBlock[currByte] = byte(testByte)

                correct = ServerDecryptCheckStub(currBlockText, attackBlock)

                if correct {
                    fmt.Println(attackBlock)
                    break
                }
            }

            if !correct {
                return nil, errors.New("Could not find a correct attack byte for currBlock " + strconv.Itoa(currBlock) +
                                       " and byte " + strconv.Itoa(currByte))
            }

            //Set the plaintext for this byte.
            plaintext[(currBlock * blocksize) + currByte] = prevBlock[currByte] ^ attackBlock[currByte] ^ padValue
        }
    }

    return plaintext, nil
}

func main() {
    plaintext := "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="

    GenerateAESKey()
    GenerateAESIV()

    ciphertext, _ := cryptolib.EncryptCBC([]byte(plaintext), aesIV, aesKey)

    decryptedPlaintext, err := CBCPaddingOracleAttack(ciphertext, 16)

    if err != nil {
        fmt.Println(err.Error())
    }

    fmt.Println(plaintext)
    fmt.Println(decryptedPlaintext)
    
}
