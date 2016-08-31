package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
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
	salt := data[saltOffset : saltOffset+saltLen]
	check := data[checkOffset : checkOffset+checkLen]

	var rounds uint32
	if err := binary.Read(bytes.NewReader(data[roundsOffset:]),
		binary.LittleEndian, &rounds); err != nil {
		log.Fatal(err)
	}

	try := func(pass string) bool {
		maskkey := pbkdf2.Key([]byte(pass), salt, int(rounds), 32, sha1.New)

		// AES-ECB-256_decrypt(k=maskkey, scm_key) = scr_key
		a, err := aes.NewCipher(maskkey)
		if err != nil {
			log.Fatal(err)
		}
		for i := 0; i < len(scmKey); i += a.BlockSize() {
			a.Decrypt(scmKey[i:i+a.BlockSize()], scmKey[i:i+a.BlockSize()])
		}

		// HMAC-SHA1(k=maskkey, scm_key) == sch_mac
		h := sha1.Sum(maskkey)
		mac := hmac.New(sha1.New, h[:])
		mac.Write(scmKey)
		expected := mac.Sum(nil)

		return bytes.Equal(expected, check)
	}

	f, err := os.Open("wordlist.txt")
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	i := 0
	for scanner.Scan() {
		if try(scanner.Text()) {
			log.Print(scanner.Text())
			return
		}
		i++
		if i%256 == 0 {
			log.Print(i)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
