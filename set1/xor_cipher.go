package main

import (
    "fmt"
    "encoding/hex"
)

var scoreMap = map[string]float32 {
    "a": 5, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2, "g": 2, "h": 6.1, "i": 7.0, "j": 0.2, "k": 0.8, "l": 4, "m": 2.4,
    "n": 6.7, "o": 7.5, "p": 1.9, "q": 0.1, "r": 6, "s": 6.3, "t": 9.1, "u": 2.8, "v": 1, "w": 2.4, "x": 0.2, "y": 2, "z": 0.1, 
    " ": 5, //The real plaintext may very well have spaces in it so let's consider those too!
}

func XorAgainstChar(hexString string, char byte) (string, string, error) {
    hexBytes, err := hex.DecodeString(hexString)

    if err != nil {
        fmt.Println("Error while converting hex to byte array:", err.Error())
        return "", "", err
    }

    for i, _ := range hexBytes {
        hexBytes[i] ^= char
    }

    xorString := hex.EncodeToString(hexBytes)
    plaintext := string(hexBytes)

    return xorString, plaintext, nil
}

func ScorePlaintext(plaintext string) float32 {

    score := float32(0)

    for _, char := range plaintext {
        if value, exists := scoreMap[string(char)]; exists {
            score += value
        }
    }

    return score
}

func FindBestPlaintext(hexString string) (string, float32, byte) {
    bestScore := float32(0)
    bestPlaintext := ""
    bestChar := byte(0)

    for char := byte(33); char < byte(123); char++ {
        _, plaintext, err := XorAgainstChar(hexString, char)

        if err != nil {
            panic(err)
        }

        score := ScorePlaintext(plaintext)

        if score > bestScore {
            bestScore = score
            bestPlaintext = plaintext
            bestChar = char
        }

        fmt.Println("Char:", string(char), "\n\t\tScore:", score)
        fmt.Printf("Plaintext: %q\n\n", plaintext)
    }

    return bestPlaintext, bestScore, bestChar
}


func main() {
    hexString := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    plaintext, bestScore, char := FindBestPlaintext(hexString)

    fmt.Println("Best plaintext is:", plaintext, ", with score:", bestScore, "using char:", string(char))
}