package cryptolib

import (
    "bytes"
    "testing"
    "encoding/hex"
    "crypto/rand"
)

func TestRemovePkcs7Padding(t *testing.T) {

    type removePkcs7PaddingPairs struct {
        input string
        expected string
        errorExpected bool
    }

    var removePkcs7PaddingTestCases = []removePkcs7PaddingPairs {
        {
            input: "",
            expected: "",
            errorExpected: true,
        },
        {
            input: "a",
            expected: "",
            errorExpected: true,
        },
        {
            input: "a\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F",
            expected: "a",
            errorExpected: false,
        },
        {
            input: "123456789012345\x02",
            expected: "",
            errorExpected: true,
        },
        {
            input: "1234567890\x01\x02\x03\x04\x05\x06",
            expected: "",
            errorExpected: true,
        },
        {
            input: "1234567890\x06\x06\x06\x06\x06\x06",
            expected: "1234567890",
            errorExpected: false,
        },
    }

    for _, testcase := range removePkcs7PaddingTestCases {

        actual, err := RemovePkcs7Padding([]byte(testcase.input))

        if !testcase.errorExpected && err != nil {
            t.Error("Unexpected error encountered with test case:", []byte(testcase.input), "error:", err.Error())
        } else if testcase.errorExpected && err == nil {
            t.Error("Expected an error but did not receive one with test case:", []byte(testcase.input))
        }

        if string(actual) != testcase.expected {
            t.Error("Expected:", []byte(testcase.expected), "but got:", actual)
        }
    }
}

func TestValidatePkcs7Padding(t *testing.T) {

    type validatePkcs7PaddingPairs struct {
        input string
        expected bool
    }

    var validatePkcs7PaddingTestCases = []validatePkcs7PaddingPairs {
        {
            input: "",
            expected: false,
        },
        {
            input: "a",
            expected: false,
        },
        {
            input: "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
            expected: true,
        },
        {
            input: "12345678\x08\x08\x08\x08\x08\x08\x08\x08",
            expected: true,
        },
        {
            input: "12345678\x07\x07\x07\x07\x07\x07\x07",
            expected: false,
        },
        {
            input: "123456\x07\x07\x07\x07\x07\x07\x07\x06\x07\x07",
            expected: false,
        },
        {
            input: "123456\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A",
            expected: true,
        },
    }

    for _, testcase := range validatePkcs7PaddingTestCases {
        actual := ValidatePkcs7Padding([]byte(testcase.input))

        if actual != testcase.expected {
            t.Error("Expected", testcase.expected, "but got", actual, "for testcase:", []byte(testcase.input))
        }
    }
}

func TestIsECB(t *testing.T) {

    type isEcbTestPairs struct {
        input string
        blocksize int
        shouldDetectEcb bool
        errorExpected bool
    }

    var isEcbTestCases = []isEcbTestPairs {
        {
            input: "",
            blocksize: 16,
            shouldDetectEcb: false,
            errorExpected: false,
        },
        {
            input: "1234567890123456",
            blocksize: 16,
            shouldDetectEcb: false,
            errorExpected: false,
        },
        {
            input: "12345678901234561234567890123456",
            blocksize: 16,
            shouldDetectEcb: true,
            errorExpected: false,
        },
        {
            input: "1234567890123456hereanotherblock1234567890123456",
            blocksize: 16,
            shouldDetectEcb: true,
            errorExpected: false,
        },
    }

    for _, testcase := range isEcbTestCases {
        //Randomly generate a valid key
        key := make([]byte, 16)
        _, _ = rand.Read(key)

        ciphertext, _ := EncryptECB([]byte(testcase.input), key, true)

        //Now check if it's ECB!
        isEcb, err := IsECB(ciphertext, testcase.blocksize)

        if !testcase.errorExpected && err != nil {
            t.Error("Unexpected error encountered with plaintext", testcase.input, "error:", err.Error())
        } else if testcase.errorExpected && err == nil {
            t.Error("Expected an error but did not receive one with plaintext", testcase.input)
        }

        if testcase.shouldDetectEcb && !isEcb {
            t.Error("Should have detected ecb for testcase:", testcase.input, "but did not")
        } else if !testcase.shouldDetectEcb && isEcb {
            t.Error("Incorrectly identified testcase:", testcase.input, "as ecb")
        }
    }

}

func TestCBCEncryptDecrypt (t *testing.T) {

    type cbcTestPairs struct {
        input string
        expected string
        key string
        iv string
        errorExpected bool
    }

    var cbcTestCases = []cbcTestPairs {
        {
            input: "YELLOW SUBMARINE",
            key: "YELLOW SUBMARINE",
            iv: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            expected: "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
            errorExpected: false,
        },
        {
            input: "too short",
            expected: "too short\x07\x07\x07\x07\x07\x07\x07",
            iv: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            key: "this key is way too long",
            errorExpected: false,
        },
        {
            input: "long plaintext that is a multiple of the key ok.",
            expected: "long plaintext that is a multiple of the key ok.\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
            iv: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            key: "this is my key k",
            errorExpected: false,
        },
        {
            input: "Doesn't matter because our key size is too small!",
            expected: "",
            iv: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            key: "tiny!",
            errorExpected: true,
        },
    }

    for _, testcase := range cbcTestCases {
        //Attempt to encrypt and then decrypt the input. We'd better have the same text spat back out!
        ciphertext, err := EncryptCBC([]byte(testcase.input), []byte(testcase.iv), []byte(testcase.key))

        if !testcase.errorExpected && err != nil {
            t.Error("Unexpected error encountered with plaintext", testcase.input, "and key", testcase.key, "error:", err.Error())
        } else if testcase.errorExpected && err == nil {
            t.Error("Expected an error but did not receive one with plaintext", testcase.input, "and key", testcase.key)
        }

        actual := []byte("")

        if err == nil {
            var decryptErr error
            actual, decryptErr = DecryptCBC(ciphertext, []byte(testcase.iv), []byte(testcase.key))

            if decryptErr != nil {
                t.Error("Unexpected error encountered with plaintext", testcase.input, "and key", testcase.key, "error:", decryptErr.Error())
            }
        }

        if !bytes.Equal(actual, []byte(testcase.expected)) {
            t.Error("Expected:", []byte(testcase.expected), "but got:", actual, "(input: ", testcase.input, ")")
        }

    }
}

func TestGetAESBlocks (t *testing.T) {

    type getAESBlocksTestPairs struct {
        input string
        blockSize int
        canPad bool
        expected []string
        errorExpected bool
    }

    var getAESBlockTestCases = []getAESBlocksTestPairs {
        {
            input: "1234567890123456",
            blockSize: 16,
            canPad: true,
            expected: []string{ "1234567890123456" },
            errorExpected: false,
        },
        {
            input: "1234567890",
            blockSize: 16,
            canPad: true,
            expected: []string{ "1234567890\x06\x06\x06\x06\x06\x06" },
            errorExpected: false,
        },
        {
            input: "1234567890",
            blockSize: 16,
            canPad: false,
            expected: nil,
            errorExpected: true,
        },
        {
            input: "",
            blockSize: 16,
            canPad: true,
            expected: []string{ "\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16" },
            errorExpected: false,
        },
        {
            input: "1234567890",
            blockSize: 2,
            canPad: true,
            expected: []string{ "12", "34", "56", "78", "90" },
            errorExpected: false,
        },
    }

    for _, testcase := range getAESBlockTestCases {
        actual, err := GetAESBlocks([]byte(testcase.input), testcase.blockSize, testcase.canPad)

        if !testcase.errorExpected && err != nil {
            t.Error("Unexpected error encountered with input", testcase.input, "and blocksize", testcase.blockSize, "error:", err.Error())
        } else if testcase.errorExpected && err == nil {
            t.Error("Expected an error but did not receive one with input", testcase.input, "and blocksize", testcase.blockSize)
        }

        for i, _ := range actual {
            if !bytes.Equal(actual[i], []byte(testcase.expected[i])) {
                t.Error("Expected:", []byte(testcase.expected[i]), "but got:", actual[i])
            }
        }
    }
}

func TestECBEncryptDecrypt (t *testing.T) {

    type ecbTestPairs struct {
        input string
        expected string
        key string
        errorExpected bool
    }

    var ecbTestCases = []ecbTestPairs {
        {
            input: "YELLOW SUBMARINE",
            key: "YELLOW SUBMARINE",
            expected: "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
            errorExpected: false,
        },
        {
            input: "too short",
            expected: "too short\x07\x07\x07\x07\x07\x07\x07",
            key: "this key is way too long",
            errorExpected: false,
        },
        {
            input: "long plaintext that is a multiple of the key ok.",
            expected: "long plaintext that is a multiple of the key ok.\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
            key: "this is my key k",
            errorExpected: false,
        },
        {
            input: "Doesn't matter because our key size is too small!",
            expected: "",
            key: "tiny!",
            errorExpected: true,
        },
    }

    for _, testcase := range ecbTestCases {
        //Attempt to encrypt and then decrypt the input. We'd better have the same text spat back out!
        ciphertext, err := EncryptECB([]byte(testcase.input), []byte(testcase.key), true)

        if !testcase.errorExpected && err != nil {
            t.Error("Unexpected error encountered with plaintext", testcase.input, "and key", testcase.key, "error:", err.Error())
        } else if testcase.errorExpected && err == nil {
            t.Error("Expected an error but did not receive one with plaintext", testcase.input, "and key", testcase.key)
        }

        actual := []byte("")

        if err == nil {
            actual, _ = DecryptECB(ciphertext, []byte(testcase.key))
        }

        if !bytes.Equal(actual, []byte(testcase.expected)) {
            t.Error("Expected:", []byte(testcase.expected), "but got:", actual, "(input: ", testcase.input, ")")
        }

    }
}


func TestPkcs7Padding (t *testing.T) {

    type pkcs7TestPairs struct {
        input string
        paddedLength int
        expected string
    }

    var pkcs7TestCases = []pkcs7TestPairs {
        {
            input: "",
            expected: "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
        },
        {
            input: "YELLOW SUBMARINE",
            expected: "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
        },
        {
            input: "This is a string longer than a single block",
            expected: "This is a string longer than a single block\x05\x05\x05\x05\x05",
        },
    }

    for _, testcase := range pkcs7TestCases {
        rawBytes := []byte(testcase.input)
        actual := Pkcs7Padding(rawBytes)

        if !bytes.Equal(actual, []byte(testcase.expected)) {
            t.Error("Expected:", []byte(testcase.expected), "but got:", actual)
        }
    }

}


func TestCalculateHammingDistance(t *testing.T) {

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

func TestXorAgainstChar(t *testing.T) {

    type testXorAgainstCharPairs struct {
        inputString string
        inputChar byte
        expected string
    }

    var testXorAgainstCharCases = []testXorAgainstCharPairs {
        {
            inputString: "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
            inputChar: 99, //c
            expected: "7854545052555c1b76781c481b5752505e1b5a1b4b544e555f1b545d1b595a585455",
        },
        {
            inputString: "",
            inputChar: 99,
            expected: "",
        },
        {
            inputString: "",
            inputChar: 0,
            expected: "",
        },
    }

    for _, testCase := range testXorAgainstCharCases {

        inputBytes, _ := hex.DecodeString(testCase.inputString)
        expectedBytes, _ := hex.DecodeString(testCase.expected)

        actual := XorAgainstChar(inputBytes, testCase.inputChar)

        if !bytes.Equal(actual, expectedBytes) {
            t.Error("Expected:", expectedBytes, "but got:", actual)
        }
    }
}

func TestScorePlaintext(t *testing.T) {

    type testScorePlaintextPairs struct {
        input string
        expected float32
    }

    var testScorePlaintextCases = []testScorePlaintextPairs {
        {
            input: "1234556",
            expected: float32(0),
        },
        {
            input: "",
            expected: float32(0),
        },
        {
            input: "eee",
            expected: float32(38.1),
        },
        {
            input: "this is a test",
            expected: float32(99),
        },
    }


    for _, testCase := range testScorePlaintextCases {

        inputBytes := []byte(testCase.input)

        actual := ScorePlaintext(inputBytes)

        if actual != testCase.expected {
            t.Error("Expected:", testCase.expected, "but got:", actual)
        }

    }
}

func TestRepeatingKeyXor(t *testing.T) {

    type testRepeatingKeyXorPairs struct {
        input string
        key string
        expected string
        errorExpected bool
    }

    var testRepeatingKeyXorCases = []testRepeatingKeyXorPairs {
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

    for _, testcase := range testRepeatingKeyXorCases {
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