package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"

	"golang.org/x/crypto/pbkdf2"
)

var scmKey = `d8 e9 b7 c2
 fd fd 74 c6 71 35 6e ba  19 f4 ec af 0e 75 b4 f8
 17 fd e8 a6 31 f3 24 fc  03 84 91 a2 7c 29 c7 8d
 61 ad 61 8a 97 f6 f0 86  75 da 29 16 26 e2 58 80
 69 07 b2 ef 6a d9 d1 77  1b 75 5f 22 5a 0a f6 a9
 c0 48 e2 4e 5d 5e 66 73  ae c5 ea 1e d5 2c ab 32
 f6 5c f3 bb 22 5b 9a 0d  f4 7e 62 e8 7e 49 46 1d
 8a b0 87 16 e7 83 4e 65  c8 6f 93 4f e2 71 50 ca
 5a e3 f5 28 6f cf 79 9e  03 93 76 28 0d 98 a4 24
 e2 5a bb 90 67 49 9c 6f  ff 0d 1c 87 36 dd 15 c5
 3d 1d 49 6c ec 85 e9 d6  4b e3 89 2a 52 91 3a 41
 1a 75 3f ad 0f 74 5d 04  0b 2d f5 d4 18 bf 54 9e
 45 d3 c6 0a f9 62 13 fa  88 a7 a5 ef 7e b0 64 ce
 92 05 63 7e f0 53 b0 bd  5c 81 3a 4e 41 c2 f3 08
 4d 34 12 e6 e7 5a 23 bd  77 99 3c 20 14 63 d7 bb
 51 15 62 45 9f 92 fd 6c  af e1 12 a2 0f 8e 4a 62
 fd 52 73 e2 ed 9e 34 7c  19 82 ea 1b a6 55 fc 9e
 cf 61 6a fc 4f 18 34 0c  14 b9 45 41 c4 5f 78 d2
 ee d7 db 3d 69 ca 5e 1b  c3 7f c0 4c 78 41 b5 3d
 08 4d e2 ea a7 53 c5 4b  c0 3d e8 23 46 6b 4d dd
 ea 08 56 a1 18 78 b9 ba  c1 54 cc 2f d0 4a 3e 89
 f1 38 7b 04 87 12 93 6f  3c f5 6e c4 f8 8b ea 56
 ee 77 c8 95 af 8f aa 3a  73 c6 82 51 94 fe 22 8c
 03 71 cd 2a 0f 00 bf ee  41 b9 30 18 cf 12 00 31
 c0 0e 57 6c 4e 46 01 aa  d3 62 4b f6 c3 0a 88 70
 92 96 6b 6d ef f1 3b 67  d2 e7 f2 5d 98 b0 2d b5
 48 71 85 3f 92 1f fe fe  d0 11 fc bf 99 5c fe 8f
 b7 3d b3 c4 c9 4b cb 0a  9d a2 ca 94 73 43 7f 9d
 37 03 cf 22 00 2a 0a d5  9c 01 28 d0 ed f6 fc db
 c1 55 86 e4 88 93 fd a5  93 3f 8d c3 fe 70 bd 8a
 db 85 b8 ec b3 9c 86 4f  6c db af 4d 0e a9 46 c5
 d6 5a cd d0 d1 8a 9c 50  29 86 ce 73 a4 85 9c 24
 bc 95 ef 4d 76 d4 24 47  d5 25 24 95 2d 47 39 7e
 c4 2b 1c 4a d4 4e 13 31  20 6f 79 af e5 0b 67 a2
 ea ac 2c 94 5a c2 9e 77  ca 12 87 19 dd 1b 96 81
 08 a5 e7 48 e6 77 b5 bc  c1 eb 82 e6 41 62 e1 00
 70 51 8b e2 4a b6 42 f4  c9 d3 f8 b2 a2 f9 28 df
 be 5c 3f 43 33 5f ed 4b  59 4d ca 91 c0 23 f0 e6
 b3 6f 8a 51 e8 82 91 60  ea 34 73 02 65 01 e6 69
 69 41 e6 5a 33 e5 28 ef  69 96 86 59 e3 81 31 eb
 29 50 ca e8 d5 3a 1c a6  90 7a 9d 1a 05 68 6e bc
 b2 ef 52 30 70 f0 9c fa  e1 ab 73 61 13 87 04 1d
 4e 8e 80 f2 1f 6c 7e 48  25 ec 33 0d 86 91 64 00
 f8 ff 52 a5 cb 11 fd b7  84 40 d4 d9 01 93 c2 02
 49 58 8c eb 7c 33 f3 a5  0f 0b 23 18 ec d8 5f cc
 bb ba eb 11 cf f3 61 6e  00 cc b4 f0 02 55 33 8b
 cf ec df 96 6a f5 94 33  54 7b 20 64 30 c7 f2 5b
 1d 02 74 2d f4 95 93 1a  eb aa 83 ba 81 f9 ad fd
 f9 eb f0 02 4f 11 38 cf  80 25 c7 5e 2f fa df e1
 39 cf f6 b7 29 c9 b9 b4  3d 79 fe 34 32 a7 b2 26
 2b 17 fd ff 19 75 90 db  cc b9 f4 44 4e 40 e5 88
 2b 11 39 46 26 29 de c0  bd 88 16 b2 12 d1 8e f8
 b3 fd ec bf 24 e5 81 90  c4 bf 62 88 64 29 1b 20
 4e b2 2f 98 d6 67 f4 eb  07 11 12 69 81 2a 46 c2
 08 19 88 a0 20 8a 75 ff  36 67 67 42 34 48 d7 0b
 d7 af 85 9e e4 35 f1 52  6f e8 9e 08 1a 61 17 89
 49 d6 55 cd 56 06 6e 1c  d0 c4 5d e1 5b 2c 5e 77
 37 33 75 f0 14 09 e1 84  1d 16 2f a1 68 c9 63 4d
 32 03 6c 2e ae 97 a4 20  6a 91 b0 33 d6 ca 6a c6
 ba 4c 4b 61 2b f1 ca 07  8d e1 58 6a db 99 75 e6
 b5 91 97 a0 45 22 c2 c7  34 7d 7a af 02 a6 0f cd
 1f 43 6e 8a 68 b4 bc dd  1b 61 46 22 e3 ac 92 95
 00 ad 82 92 ec 0b 4c 1b  2f 81 3d db 50 a8 1a 9f
 a1 6a d9 5b d2 48 61 f1  65 ee 14 07 a6 38 80 f6
 88 89 d6 d5 20 29 7c f1  c3 56 c4 f2 1a d0 9b 0e
 a5 31 21 fe 32 a3 b5 c1  14 c4 31 db e5 2a 0f 18
 1f 67 c3 58 9a 6b 5c 52  c1 cc cf cf 61 4b dd fd
 60 23 09 7a c8 94 8d 88  bb 1a 66 47 f7 3f e9 84
 b2 7e 11 cc 0e 02 5f f2  de c6 9c bb de a4 71 41
 b8 36 28 e0 a6 f8 06 a6  cd ba fa fc 2a a3 36 fb
 21 51 6d 9b fd 90 93 9a  8e a4 bc c8 dd c8 8f 0d
 98 cd a9 4b 43 e5 70 b7  9e c3 d9 87 a3 de fe c5
 09 00 8c aa 38 18 bd f2  f2 17 ce 3c 95 42 3b 59
 98 e8 84 d3 b8 2d fe e8  3f b5 09 b9 8b d8 2c 26
 de 93 d7 67 11 6d 95 1a  3c 9b 77 75 a3 6d bc b1
 ba d9 b0 66 9c 8a 36 6e  2f 5d 05 a3 87 43 d8 4d
 58 b3 45 fb 07 42 70 a8  f1 e3 34 cf 01 bf 8e af
 50 e6 d3 b6 99 ac 74 b7  1e 1a 64 44 71 4c d6 b0
 df 13 5d 09 b7 92 67 b1  64 bd 18 51 6a a6 9b 70
 d6 b0 ff cd 2c 38 14 65  e1 bc 6a 07 69 9a 7b 97
 2e 2b c3 86 8a 7a a3 04  65 80 6e ff 18 f1 e7 25
 c3 3a ed 86 6d 9f fa f2  83 c7 a5 a3 3e 70 14 22
 36 3b a8 9b 12 e4 d3 40  f4 57 e5 8a 01 dd 71 7a
 eb a2 71 5f a9 c0 2e 07  e8 88 6f 53 d8 c1 ba 42
 03 f3 9b 01 3c 52 bf 49  67 0d 81 be ab 2c b7 2a
 14 83 8d 23 4e 12 b7 1b  15 e7 82 88 83 75 c0 2e
 f2 2f 00 11 7e ff 47 ce  d6 de c3 c0 d5 e4 bd 51
 2e 48 51 2b e1 95 6f 6c  b0 71 91 7e 31 36 b8 5f
 b3 ce d6 08 d0 46 a4 08  7a ae 3e cf f2 80 71 d3
 46 00 92 63 d2 4c de a4  2b e3 e2 72 15 f1 2d 4f
 68 d7 e0 d3 f2 6a d6 05  e2 6b 9f 38 7f d5 59 26
 0b 17 81 ad 13 7d fc 0d  c6 f4 c7 77 e0 50 19 6e
 8f 09 0a 2d eb ba 66 5e  51 8e ca 49 ec 02 60 01
 3c 60 78 4f cc 99 04 7e  df 08 c1 dd a4 47 fa 0c
 9e 83 46 b4 8c b9 05 68  92 e3 46 b3 dc 5d 4d b4
 c3 ef fe 00 fc c1 49 ca  fb 18 cc 46 a5 c7 b7 55
 95 ca 5e c0 a6 19 b8 bf  b8 58 ed ae 0b 68 95 7d
 6c 19 15 cc 4a 00 33 a0  8c 64 59 64 1e 38 7c 39
 c7 9a 3e 32 8e fb ee cb  f1 b7 50 42 e7 b8 69 cf
 a7 20 3a 69 a4 21 27 27  fb 37 f7 f9 57 d5 86 95
 04 d2 28 d3 5f af ff bb  8c 0e 3e 89 15 56 fd 5c
 64 c9 e4 af ff 0e ca 62  c5 a0 5f 75 6c 67 53 40
 cc 81 39 7d 4f af 0c a5  a4 56 9d 53 2a 3a 75 54
 bb 6f e2 ca 63 31 57 1d  fb bb dc 61 92 68 7c 4d
 0a a7 c2 b7 f2 4a b6 6d  ec 20 6c 0f 02 3f ae 29
 a0 31 4b 8f 6c 3f 77 f1  d6 9a f2 c7 3e 5a fc 01
 15 bb be 36 fc 6a b2 9f  7e a3 cc a7 5b 2d f9 54
 62 49 cf a3 11 f9 76 8c  87 e5 42 3a 96 09 2c 55
 4f 46 68 55 e4 18 70 df  07 50 40 46 04 0a 31 de
 52 49 01 13 00 3c d6 f7  88 c6 f5 86 d3 0b d5 2a
 e8 60 e6 6f 37 28 4c 16  05 84 a5 06 bc 4c f8 79
 e6 32 dc fb bc 6c c8 5b  fe ee e7 c3 56 8b 12 e7
 22 ff 4f 44 fe dc 0e 1f  85 9a b8 41 38 fd 6b 9a
 90 07 29 5b 3f dc 25 85  dd 70 71 0c c4 23 88 92
 a7 cb 85 ab e8 f3 c6 f1  10 93 7b d2 7e 90 38 1a
 23 97 a4 3d 12 8c 3a 51  58 cf 04 3b bf 13 e8 5d
 fe 94 dc 43 05 c3 c4 ca  87 36 24 d5 25 b5 78 20
 98 ef 5f 91 5a ac 64 09  07 dd e0 d8 69 c4 3b a9
 64 ae 10 6a 28 72 37 a3  ef b7 e7 73 56 1f 1f c6
 50 b5 81 ac a5 df ce 21  86 42 91 81 47 32 ae fc
 fd 4c 54 ab 96 93 a4 f5  10 f8 81 67 5c 96 31 ca
 e0 24 68 60 95 a9 46 3a  5f dc 7d 77 2a c4 2f 4e
 60 b5 63 eb 0a 10 18 ae  93 c2 6d 05 23 21 0f 72
 33 c8 a4 d7 f6 51 1a 77  86 8b a8 fb e5 1a fc 84
 cb 53 e2 cc 55 fc 03 55  cb af c3 68 e0 e0 cc 13
 b1 18 6b 47 f7 4d 74 94  fd cd 3d 5d 63 93 0a 50
 06 f0 69 0c 59 fb 41 85  ac f0 5e a0 88 62 f4 8a
 ad 15 a6 4b ed 4d 3e 8a  61 5c f8 a2 7c 75 56 a7
 bd aa 55 a2 b9 14 28 7a  55 df a9 ba`

var rounds = 0x2000

var salt = `
  50 1f db 08 97 6d 2c 40
  63 fb ff 91 5e 6c 75 fc  b9 44 86 16 77 1f 6d 65
  4d 64 f8 56 ab 11 83 c7  7b 01 ac a0 f2 69 51 83
  b3 41 df c4 83 21 7a ce  75 37 3d f8 80 4f 6d 36 
  06 63 55 15 ff de 7d 7a  b1 ac dd 0c f8 41 63 bb 
  42 cc a6 85 4a b5 52 f4  50 ec 9f 05 3f 9d 8b 8d
  64 fe 85 ba 8f ce 08 87  97 e2 8d 35 2c 9d 6a 2d
  cb 8c e2 7e 72 65 7d 7e  56 76 87 89 e6 ba cc 49
  bd 84 43 ef e6 3e 07 d6 
`

func decode(s string) []byte {
	s = regexp.MustCompile(` |\n`).ReplaceAllString(s, "")
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func main() {
	scmKey := decode(scmKey)
	salt := decode(salt)

	maskkey := pbkdf2.Key([]byte("password"), salt, rounds, 32, sha1.New)

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
	expectedMAC := mac.Sum(nil)

	fmt.Print(hex.Dump(expectedMAC))
}
