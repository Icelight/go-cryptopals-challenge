package main

import (
    "fmt"
    "strings"
    "net/url"
    "crypto/rand"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

var prefix string = "comment1=cooking%20MCs;userdata="
var suffix string = ";comment2=%20like%20a%20pound%20of%20bacon"

var aesKey []byte
var iv []byte

func GenerateAESKey() []byte {
    if aesKey != nil {
        return aesKey
    }

    aesKey = make([]byte, 16)

    _, err := rand.Read(aesKey)

    if err != nil { panic(err) }

    return aesKey
}

func GenerateAESIV() []byte {
    if iv != nil {
        return iv
    }

    iv = make([]byte, 16)

    _, err := rand.Read(iv)

    if err != nil { panic(err) }

    return iv
}

func PadAndEncryptProfile(userData string) []byte {
    sanitized := url.QueryEscape(userData)

    input := []byte(prefix + sanitized + suffix);

    GenerateAESKey()
    GenerateAESIV()

    ciphertext, _ := cryptolib.EncryptCBC(input, iv, aesKey)

    return ciphertext
}

func DecryptProfileAndCheckAdmin(ciphertext []byte) bool {
    GenerateAESKey()
    GenerateAESIV()
    plaintext, _ := cryptolib.DecryptCBC(ciphertext, iv, aesKey)
    plaintext, _ = cryptolib.RemovePkcs7Padding(plaintext)

    if strings.Contains(string(plaintext), ";admin=true;") {
        return true
    }

    return false
}

func CreateAdminProfileAttack() []byte {
    //Generate a user data string such that our poisoned ;admin=true string is in its own block
    //(as we know that the prefix the site uses is a multiple of the block size already).
    attackString := "0123456789012345_admin_true"
    ciphertext := PadAndEncryptProfile(attackString)

    //Our user data starts at the third block. Let's corrupt the first character of that block as well as
    //6 characters later, both of which correspond to entries in our admin string as well.
    ciphertext[32] ^= '_' ^ ';'
    ciphertext[38] ^= '_' ^ '='

    return ciphertext;
}

func main() {
    attackProfile := CreateAdminProfileAttack()

    if DecryptProfileAndCheckAdmin(attackProfile) {
        fmt.Println("Attack worked! You now have admin rights.")
    } else {
        fmt.Println("The attack failed...")
    }   
}
