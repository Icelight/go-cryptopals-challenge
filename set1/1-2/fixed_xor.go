package main

import (
    "fmt"
    "errors"
    "encoding/hex"
)

//Assumes that input1 and input2 are already of equal length.
func xorOverArray(input1 []byte, input2 []byte) []byte {
    
    outputBytes := make([]byte, len(input1))

    for i, _ := range input1 {
        if i > len(input2) {
            break
        }

        outputBytes[i] = input1[i] ^ input2[i]
    }

    return outputBytes
}

func FixedXor(input1, input2 string) (string, error) {
    if len(input1) != len(input2) {
        return "", errors.New("Length of input strings were not the same")
    }

    input1HexBytes, err := hex.DecodeString(input1)

    if err != nil {
        return "", err
    }

    input2HexBytes, err := hex.DecodeString(input2)

    if err != nil {
        return "", err
    }

    xorBytes := xorOverArray(input1HexBytes, input2HexBytes)
    outputString := hex.EncodeToString(xorBytes)

    return outputString, nil
}

func main() {
    input1 := "1c0111001f010100061a024b53535009181c"
    input2 := "686974207468652062756c6c277320657965"

    output, err := FixedXor(input1, input2)

    if err != nil { panic(err) }

    fmt.Println(output)
}
