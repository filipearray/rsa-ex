package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
)

var privateKey *rsa.PrivateKey

func init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
}

// Encrypt encrypts a string using RSA public key and returns it as a base64 string
func Encrypt(data string) (string, error) {
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, []byte(data), nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

// Decrypt decrypts a base64 string using RSA private key and returns the original string
func Decrypt(data string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, decodedBytes, nil)
	if err != nil {
		return "", err
	}
	return string(decryptedBytes), nil
}

func main() {
	http.HandleFunc("/encrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		text := r.FormValue("text")
		encrypted, err := Encrypt(text)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(encrypted))
	})

	http.HandleFunc("/decrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		text := r.FormValue("text")
		decrypted, err := Decrypt(text)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(decrypted))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fmt.Println("Server running on port 8080")
	http.ListenAndServe(":8080", nil)
}