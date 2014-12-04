package main

import (
    "testing"
    "bytes"
)

type hexTo64TestPairs struct {
    input string
    expectedString string
    expectedBytes []byte
}

var hexTo64Cases = []hexTo64TestPairs {
    {
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        []byte {83, 83, 100, 116, 73, 71, 116, 112, 98, 71, 120, 112, 98, 109, 99, 103, 101, 87, 57, 49, 99, 105, 66, 105, 
                99, 109, 70, 112, 98, 105, 66, 115, 97, 87, 116, 108, 73, 71, 69, 103, 99, 71, 57, 112, 99, 50, 57, 117, 98,
                51, 86, 122, 73, 71, 49, 49, 99, 50, 104, 121, 98, 50, 57, 116,},
    },
    {
        "0123456789ABCDEF",
        "ASNFZ4mrze8=",
        []byte {65, 83, 78, 70, 90, 52, 109, 114, 122, 101, 56, 61,},
    },
}

func TestHexTo64String(t *testing.T) {

    for _, testcase := range hexTo64Cases {
        actual, err := HexTo64String(testcase.input)

        if err != nil {
            t.Error("Error returned by HexTo64String:", err.Error())
        }

        if actual != testcase.expectedString {
            t.Error("Expected:", testcase.expectedString, "but got:", actual)
        }
    }
}

func TestHexTo64Bytes(t *testing.T) {

    for _, testcase := range hexTo64Cases {
        actual, err := HexTo64Bytes(testcase.input)

        if err != nil {
            t.Error("Error returned by HexTo64Bytes:", err.Error())
        }

        if !bytes.Equal(actual, testcase.expectedBytes) {
            t.Error("Expected:", testcase.expectedBytes, "but got:", actual)
        }
    }
}