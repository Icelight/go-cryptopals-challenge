package main

import (
    "testing"
)

type hammingDistanceTestPairs struct {
    first string
    second string
    expected int
    errorExpected bool
}

var hammingDistanceTestCases = []hammingDistanceTestPairs {
    {
        first: "this is a test",
        second: "wokka wokka!!!",
        expected: 37,
        errorExpected: false,
    },
    {
        first: "bad",
        second: "length",
        expected: -1,
        errorExpected: true,
    },
}

func TestCalculateHammingDistance(t *testing.T) {

    for _, testcase := range hammingDistanceTestCases {
        dist, err := CalculateHammingDistance([]byte(testcase.first), []byte(testcase.second))

        if !testcase.errorExpected && err != nil {
            t.Error("Unexpected error was returned:", err.Error())
        } else if testcase.errorExpected && err == nil {
            t.Error("Error was expected but not returned!")
        }

        if dist != testcase.expected {
            t.Error("With input of:", testcase.first, "and:", testcase.second, "\nExpected:", testcase.expected, "but got:", dist)
        }
    }

}