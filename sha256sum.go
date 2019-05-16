package sha256sum

import (
	"encoding/binary"
	"fmt"
	"os"
)

var (
	k = []uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}
)

func rightRotate(value uint32, shift uint) uint32 {
	return (value >> shift) | (value << (32 - shift))
}

func preProcess(msg []byte, length uint) []byte {
	msg = msg[:length]      // The 64 byte buffer fills everything with zero, we don't want those zeroes
	K := 448 - 8*length - 1 // K, the number of zeroes for padding to 512-bit
	// fmt.Println("length:", length)
	// fmt.Println("K:", K)
	padding := make([]byte, K/8)
	size := make([]byte, 8)
	binary.BigEndian.PutUint64(size, 8*uint64(length))

	msg = append(msg, 0x80)       // Add 1 bit
	msg = append(msg, padding...) // Add zero paddings
	msg = append(msg, size...)    // Add big-endian size of message
	// fmt.Println("len(msg):", len(msg))
	// fmt.Println(msg)
	return msg
}

// Sha256Sum generates a SHA-256 hash of a file
// Based off of the algorithm in the wikipedia:
// https://en.wikipedia.org/wiki/SHA-2#Pseudocode
func Sha256Sum(filepath string) (string, error) {
	var h0, h1, h2, h3, h4, h5, h6, h7 uint32
	h0 = 0x6a09e667
	h1 = 0xbb67ae85
	h2 = 0x3c6ef372
	h3 = 0xa54ff53a
	h4 = 0x510e527f
	h5 = 0x9b05688c
	h6 = 0x1f83d9ab
	h7 = 0x5be0cd19

	// Open file for reading
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 512 bit buffer to hold our data from file
	buf := make([]byte, 32)
	for numBytes, err := file.Read(buf); err == nil && numBytes > 0; numBytes, err = file.Read(buf) {
		// Preprocessing
		var bmsg []byte
		bmsg = preProcess(buf, uint(numBytes))
		// if numBytes < 64 {
		// 	bmsg = preProcess(buf, uint(numBytes))
		// } else {
		// 	bmsg = buf
		// }

		w := make([]uint32, 64)
		for i, j := 0, 0; i < 16; i, j = i+1, j+4 {
			w[i] = uint32(bmsg[j])<<24 | uint32(bmsg[j+1])<<16 | uint32(bmsg[j+2])<<8 | uint32(bmsg[j+3])
		}

		for i := 16; i < 64; i++ {
			s0 := rightRotate(w[i-15], 7) ^ rightRotate(w[i-15], 18) ^ (w[i-15] >> 3)
			s1 := rightRotate(w[i-2], 17) ^ rightRotate(w[i-2], 19) ^ (w[i-2] >> 10)
			w[i] = w[i-16] + s0 + w[i-7] + s1
		}

		a := h0
		b := h1
		c := h2
		d := h3
		e := h4
		f := h5
		g := h6
		h := h7

		for i := 0; i < 64; i++ {
			S1 := rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)
			ch := (e & f) ^ (^e & g)
			temp1 := h + S1 + ch + k[i] + w[i]
			S0 := rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := S0 + maj

			h = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2
		}
		h0 = h0 + a
		h1 = h1 + b
		h2 = h2 + c
		h3 = h3 + d
		h4 = h4 + e
		h5 = h5 + f
		h6 = h6 + g
		h7 = h7 + h
	}

	digest := fmt.Sprintf("%x%x%x%x%x%x%x%x", h0, h1, h2, h3, h4, h5, h6, h7)
	return digest, nil
}
