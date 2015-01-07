package cryptolib

import (
    "strings"
    "errors"
    "crypto/aes"
)

func IsECB(ciphertext []byte, blocksize int) (bool, error) {

    isEcb := false

    if blocksize > len(ciphertext) || len(ciphertext) % blocksize != 0 {
        err := errors.New("Blocksize must be ≤ ciphertext length and ciphertext length must be a multiple of blocksize")
        return isEcb, err
    }

    blockMap := make(map[string]int)
    totalDupes := 0

    for i := 0; i < len(ciphertext); i += blocksize {

        block := ciphertext[i:i+blocksize]

        _, ok := blockMap[string(block)]

        if ok {
            totalDupes++
        } else {
            blockMap[string(block)] = 1
        }

    }

    if totalDupes > 0 {
        isEcb = true
    } 

    return isEcb, nil
}

//We will pad the entire data if canPad is true.
func GetAESBlocks(data []byte, blockSize int, canPad bool) ([][]byte, error) {
    var paddedData []byte

    if len(data) % blockSize != 0 {
        if canPad {
            paddedData = Pkcs7Padding(data)
        } else {
            err := errors.New("Data length was not a multiple of the blocksize and can not be padded")
            return nil, err
        }
    } else {
        paddedData = data
    }

    numBlocks := len(paddedData) / blockSize
    blocks := make([][]byte, numBlocks)

    for i, block := 0, 0; i < len(paddedData); i += blockSize {
        blocks[block] = paddedData[i:i + blockSize]
        block++
    }

    return blocks, nil
}

func EncryptCBC(plaintext, iv, key []byte) ([]byte, error) {

    paddedPlaintext := Pkcs7Padding(plaintext)

    //Build up all of our blocks ahead of time.
    blocks, err := GetAESBlocks(paddedPlaintext, 16, true)

    if err != nil { return nil, err }

    prevBlock := iv
    var ciphertext []byte

    //For each block:
    // xor it with the previous block
    // Encrypt the result
    for _, block := range blocks {
        xorBlock, err := RepeatingKeyXor(prevBlock, block)

        if err != nil { return nil, err }

        cipherBlock, err := EncryptECB(xorBlock, key, false)

        if err != nil { return nil, err }

        ciphertext = append(ciphertext, cipherBlock...)
        prevBlock = cipherBlock
    }

    return ciphertext, nil 
}

func DecryptCBC(ciphertext, iv, key []byte) ([]byte, error) {

    //Build up all of our blocks ahead of time.
    blocks, err := GetAESBlocks(ciphertext, 16, false)

    if err != nil { return nil, err }

    prevBlock := iv
    var plaintext []byte

    //For each block:
    // Decrypt the block
    // xor it with the previous block
    for _, block := range blocks {
        cipherBlock, err := DecryptECB(block, key)

        if err != nil { return nil, err }

        plainBlock, err := RepeatingKeyXor(prevBlock, cipherBlock)

        if err != nil { return nil, err }

        plaintext = append(plaintext, plainBlock...)
        prevBlock = block
    }

    return plaintext, nil
}

func RemovePkcs7Padding(plaintext []byte) ([]byte, error) {
    validPadding := ValidatePkcs7Padding(plaintext)

    if !validPadding {
        return nil, errors.New("Padding was not valid")
    }

    paddingLen := plaintext[len(plaintext) - 1]
    trimmedPlaintext := make([]byte, len(plaintext) - int(paddingLen))
    copy(trimmedPlaintext, plaintext)

    return trimmedPlaintext, nil
}

func ValidatePkcs7Padding(plaintext []byte) bool {

    if (len(plaintext) < 16) { return false}

    paddingNum := plaintext[len(plaintext) - 1]

    if paddingNum <= 0 || paddingNum > 16 { return false }

    for i := 1; i <= int(paddingNum); i++ {
        if plaintext[len(plaintext) - i] != paddingNum { return false }
    }

    return true;
} 

func Pkcs7Padding(text []byte) []byte {

    paddingLength := 16 - (len(text) % 16);

    paddedText := make([]byte, len(text) + paddingLength)
    copy(paddedText, text)

    for i := len(text); i < len(paddedText); i++ {
        paddedText[i] = byte(paddingLength)
    }

    return paddedText
}

func EncryptECB(plaintext, key []byte, shouldPad bool) ([]byte, error) {
    blockCipher, err := aes.NewCipher(key)

    if err != nil { return nil, err }

    blockSize := blockCipher.BlockSize()

    paddedPlaintext := plaintext;

    if (shouldPad || len(plaintext) % 16 != 0) {
        paddedPlaintext = Pkcs7Padding(plaintext)
    }

    ciphertext := make([]byte, len(paddedPlaintext))

    for i := 0; i < len(paddedPlaintext); i+= blockSize {
        blockCipher.Encrypt(ciphertext[i:i+blockSize], paddedPlaintext[i:i+blockSize])
    }

    return ciphertext, nil
}

func DecryptECB(ciphertext, key []byte) ([]byte, error) {
    blockCipher, err := aes.NewCipher(key)

    if err != nil { return nil, err }

    blockSize := blockCipher.BlockSize()

    if len(ciphertext) % blockSize != 0 { 
        err := errors.New("Ciphertext must be a multiple of the blocksize")
        return nil, err
    }

    plaintext := make([]byte, len(ciphertext))

    for i := 0; i < len(plaintext); i += blockSize {
        blockCipher.Decrypt(plaintext[i:i+blockSize], ciphertext[i:i+blockSize])
    }

    return plaintext, nil
}

func XorAgainstChar(bytes []byte, char byte) []byte {

    xored := make([]byte, len(bytes))

    for i, _ := range bytes {
        xored[i] = bytes[i] ^ char
    }

    return xored
}

func RepeatingKeyXor(plainBytes, keyBytes []byte) ([]byte, error) {

    if len(keyBytes) <= 0 {
        err := errors.New("Key must have a length of at least one")
        return nil, err
    }
    
    cipherBytes := make([]byte, len(plainBytes))

    for i, char := range plainBytes {
        cipherBytes[i] = char ^ keyBytes[i % len(keyBytes)]
    }

    return cipherBytes, nil
}

var scoreMap = map[string]float32 {
    "a": 5, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2, "g": 2, "h": 6.1, "i": 7.0, "j": 0.2, "k": 0.8, "l": 4, "m": 2.4,
    "n": 6.7, "o": 7.5, "p": 1.9, "q": 0.1, "r": 6, "s": 6.3, "t": 9.1, "u": 2.8, "v": 1, "w": 2.4, "x": 0.2, "y": 2, "z": 0.1, 
    " ": 5, //The real plaintext may very well have spaces in it so let's consider those too!
}

func ScorePlaintext(plaintext []byte) float32 {

    score := float32(0)

    for _, char := range plaintext {
        if value, exists := scoreMap[strings.ToLower(string(char))]; exists {
            score += value
        }
    }

    return score
}

func FindBestPlaintext(bytes []byte) (string, float32, byte) {
    bestScore := float32(0)
    bestPlaintext := ""
    bestChar := byte(0)

    for char := byte(30); char < byte(130); char++ {
        xorBytes := XorAgainstChar(bytes, char)

        score := ScorePlaintext(xorBytes)

        if score > bestScore {
            bestScore = score
            bestPlaintext = string(xorBytes)
            bestChar = char
        }

    }

    return bestPlaintext, bestScore, bestChar
}

func CalculateHammingDistance(first []byte, second []byte) (int, error) {

    if len(first) != len(second) {
        err := errors.New("Input byte arrays must be of the same length")
        return -1, err
    }

    distance := 0
    xor := make([]byte, len(first))

    for i, _ := range first {
        xor[i] = first[i] ^ second[i]
    }

    for _, val := range xor {
        for val > 0 {
            distance++
            val &= val - 1
        }
    }

    return distance, nil
}