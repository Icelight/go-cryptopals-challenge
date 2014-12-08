package main

import (
    "testing"
)

type testPairs struct {
    input1 string
    input2 string
    expected string
    shouldThrowError bool
}

var testCases = []testPairs {
    {
        input1: "1c0111001f010100061a024b53535009181c",
        input2: "686974207468652062756c6c277320657965",
        expected: "746865206b696420646f6e277420706c6179",
        shouldThrowError: false,
    },
    {
        input1: "1234567",
        input2: "123456",
        expected: "",
        shouldThrowError: true,
    },
    {
        input1: "123456789",
        input2: "",
        expected: "",
        shouldThrowError: true,
    },
    {
        input1: "123",
        input2: "123456789ab",
        expected: "",
        shouldThrowError: true,
    },
    {
        input1: "",
        input2: "123",
        expected: "",
        shouldThrowError: true,
    },
}

func TestFixedXor(t *testing.T) {

    for _, testcase := range testCases {
        actual, err := FixedXor(testcase.input1, testcase.input2)

        if !testcase.shouldThrowError && err != nil {
            t.Error("Error returned by FixedXor:", err.Error())
        } else if testcase.shouldThrowError && err == nil {
            t.Error("Expected error from FixedXor but did not get one!")
        }

        if actual != testcase.expected {
            t.Error("Expected:", testcase.expected, "but got:", actual)
        }
    }
}
