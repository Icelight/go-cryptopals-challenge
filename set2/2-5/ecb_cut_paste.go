package main

import (
    "fmt"
    "strings"
    "strconv"
    "crypto/rand"
    "github.com/Icelight/go-cryptopals-challenge/cryptolib"
)

type UserProfile struct {
    email string
    uid int
    role string
}

var CURR_UID = 1

var aesKey []byte

func GetUserProfile(email string) *UserProfile {
    sanitized := strings.Replace(email, "&", "", -1)
    sanitized = strings.Replace(sanitized, "=", "", -1)

    user := new(UserProfile)
    user.email = email
    user.uid = CURR_UID
    user.role = "user"

    CURR_UID++

    return user    
}


func (user *UserProfile) GetEncodedProfile() string {
    return "email=" + user.email + "&uid=" + strconv.Itoa(user.uid) + "&role=" + user.role
}

func GenerateAESKey() ([]byte, error) {
    if aesKey != nil {
        return aesKey, nil
    }

    aesKey = make([]byte, 16)

    _, err := rand.Read(aesKey)

    if err != nil { panic(err) }

    return aesKey, nil
}


func EncryptUserProfile(profile string) []byte {
    key, _ := GenerateAESKey()

    ciphertext, _ := cryptolib.EncryptECB([]byte(profile), key)

    return ciphertext
}

func DecryptUserProfile(ciphertext []byte) []byte {
    key, _ := GenerateAESKey()

    plaintext, _ := cryptolib.DecryptECB(ciphertext, key)

    return plaintext
}

func main() {

    //Not including the email address, there are 18 characters in the profile string (for single-digit roles) 
    //So we need an email address with 14 characters to ensure that the role name is pushed into the last block.
    testerEmail := "icel@gmail.com"

    testerProfile := GetUserProfile(testerEmail)
    encodedProfile := testerProfile.GetEncodedProfile()

    fmt.Println("User profile plaintext:", encodedProfile)

    encryptedTesterProfile := EncryptUserProfile(encodedProfile)

    //Let's isolate the ciphertext for 'admin'. We know that the plaintext string will be:
    // "email=" which takes up 6 characters. To push "admin           " into its own block we have to
    // include 10 leading characters of text in front of our "admin" in the email.
    encryptedProfile := EncryptUserProfile(GetUserProfile("icel@emailadmin           ").GetEncodedProfile())
    isolatedRole := encryptedProfile[16:32]

    //Now swap out the isolated role into our previously created profile!
    for i := 0; i < 16; i++ {
        encryptedTesterProfile[i+32] = isolatedRole[i]
    }

    decryptedProfile := DecryptUserProfile(encryptedTesterProfile)

    fmt.Println("Modified account string:", string(decryptedProfile))    
}
