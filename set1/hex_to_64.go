package main

import (
    "fmt"
    "encoding/base64"
    "encoding/hex"
)

func HexTo64Bytes(hexString string) ([]byte, error) {
    hexBytes, err := hex.DecodeString(hexString)

    if err != nil {
        fmt.Println("Error while converting hex to byte array:", err.Error())
        return nil, err
    }

    encodedBytes := make([]byte, base64.StdEncoding.EncodedLen(len(hexBytes)))

    base64.StdEncoding.Encode(encodedBytes, hexBytes) 

    return encodedBytes, nil
}

func HexTo64String(hexString string) (string, error) {
    hexBytes, err := hex.DecodeString(hexString)

    if err != nil {
        fmt.Println("Error while converting hex to byte array:", err.Error())
        return "", err
    }

    base64String := base64.StdEncoding.EncodeToString(hexBytes)

    return base64String, nil
}