package cryptolib

import (
    "strings"
    "errors"
    "crypto/aes"
)

func DecryptECB(ciphertext, key []byte) ([]byte, error) {
    blockCipher, err := aes.NewCipher(key)

    if err != nil {
        return nil, err
    }

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