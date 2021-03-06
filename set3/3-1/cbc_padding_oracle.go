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

        var prevBlock []byte

        if currBlock == 0 {
            prevBlock = GenerateAESIV();
        } else {
            prevBlock = ciphertext[(currBlock - 1) * blocksize:currBlock*blocksize]
        }

        //Break each byte in the block, starting with the last...
        for currByte := blocksize - 1; currByte >= 0; currByte-- {

            currCipherBlock := ciphertext[currBlock * blocksize:(currBlock + 1) * blocksize]

            //Looking for padding 0x01 for the last byte, 0x02 for the second last, etc.
            padValue := byte(blocksize - currByte)

            attackBlock := make([]byte, len(currCipherBlock))
            copy(attackBlock, prevBlock) //Attackblock has to be the previous block since it acts as the IV!

            //Now copy into our attack block the bytes we've already determined from
            //our previous iterations in this block such that they will turn into
            //the padding value that we expect when decrypted. Basically the same idea as the
            //CBC Bitflipping attack
            for i := blocksize - 1; i > currByte; i-- {
                attackBlock[i] ^= plaintext[(currBlock * blocksize) + i] ^ padValue
            }

            //Aha, figured out the issue why this would fail occassionally!
            //If our plaintext required padding, we could get unlucky and, while trying to create a block with
            //valid padding, accidentally stumbling into a false positive which will screw us up as soon as we
            //work with the next byte in the block. So fill the bytes we don't care about with a bunch of 0's.
            for i := 0; i <= currByte; i++ {
                attackBlock[i] = byte(0)
            }

            correct := false

            //Now let's check all possible values for the current byte until we get a valid padding.
            for testByte := 0; testByte < 256; testByte++ {
                attackBlock[currByte] = byte(testByte)

                correct = ServerDecryptCheckStub(currCipherBlock, attackBlock)

                if correct {
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

    fmt.Println("Original input plaintext was: " + plaintext)
    fmt.Println("Decrypted plaintext is: " + string(decryptedPlaintext))
    
}
