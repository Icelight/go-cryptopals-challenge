package main

import(
    "encoding/hex"
    "bytes"
    "testing"
)

type testpairs struct {
    input string
    key string
    expected string
    errorExpected bool
}

var testcases = []testpairs {
    {
        input: "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
        key: "ICE",
        expected: "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        errorExpected: false,
    },
    {
        input: "",
        key: "TEST",
        expected: "",
        errorExpected: false,
    },
    {
        input: "Testing",
        key: "",
        expected: "",
        errorExpected: true,
    },
}

func TestRepeatingKeyXor(t *testing.T) {

    for _, testcase := range testcases {
        expected, _ := hex.DecodeString(testcase.expected)
        actual, err := RepeatingKeyXor([]byte(testcase.input), []byte(testcase.key))

        if !testcase.errorExpected && err != nil {
            t.Error("Unexpected error was returned:", err.Error())
        } else if testcase.errorExpected && err == nil {
            t.Error("Error was expected but not returned!")
        }

        if !bytes.Equal(actual, expected) {
            t.Error("Failed for input:", testcase.input, "with key:", testcase.key, "\nExpected:", testcase.expected, "but got:", string(actual))
        }
    }

}