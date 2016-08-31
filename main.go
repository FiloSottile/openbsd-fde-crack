package main

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"

	pbkdf2 "github.com/ctz/go-fastpbkdf2"
)

var (
	keyOffset    = 8556
	keyLen       = 2048
	roundsOffset = 10612
	saltOffset   = 10616
	saltLen      = 128
	checkOffset  = 10868
	checkLen     = sha1.Size
)

func main() {
	data := make([]byte, checkOffset+checkLen)
	if _, err := io.ReadFull(os.Stdin, data); err != nil {
		log.Fatal(err)
	}

	scmKey := data[keyOffset : keyOffset+keyLen]
	scrKey := make([]byte, len(scmKey))

	salt := data[saltOffset : saltOffset+saltLen]
	log.Println("Salt:")
	fmt.Fprint(os.Stderr, hex.Dump(salt))

	check := data[checkOffset : checkOffset+checkLen]
	log.Println("Checksum:")
	fmt.Fprint(os.Stderr, hex.Dump(check))

	var rounds uint32
	if err := binary.Read(bytes.NewReader(data[roundsOffset:]),
		binary.LittleEndian, &rounds); err != nil {
		log.Fatal(err)
	}
	log.Println("Rounds:", rounds)

	try := func(pass string) bool {
		maskkey := pbkdf2.Key([]byte(pass), salt, int(rounds), 32, sha1.New)

		// AES-ECB-256_decrypt(k=maskkey, scm_key) = scr_key
		a, err := aes.NewCipher(maskkey)
		if err != nil {
			log.Fatal(err)
		}
		for i := 0; i < len(scmKey); i += a.BlockSize() {
			a.Decrypt(scrKey[i:i+a.BlockSize()], scmKey[i:i+a.BlockSize()])
		}

		// HMAC-SHA1(k=maskkey, scm_key) == sch_mac
		h := sha1.Sum(maskkey)
		mac := hmac.New(sha1.New, h[:])
		mac.Write(scrKey)
		expected := mac.Sum(nil)

		return bytes.Equal(expected, check)
	}

	log.Println("Starting...")

	word1 := []string{}
	word2 := []string{}
	word3 := []string{}
	word4 := []string{}

	for _, w1 := range word1 {
		for _, w2 := range word2 {
			for _, w3 := range word3 {
				for _, w4 := range word4 {
					if try(w1 + w2 + w3 + w4) {
						log.Fatalln("YES, YES, YES!", w1+w2+w3+w4)
					}
				}
			}
		}
	}
}
