package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "fmt"
    "flag"
    "log"
    "crypto/x509"
    "encoding/pem"
    "io/ioutil"
)

func ExportPublicKeyAsPemStr(pubkey *rsa.PublicKey) string {
    pubkey_pem := string(pem.EncodeToMemory(&pem.Block{Type:  "RSA PUBLIC KEY",Bytes: x509.MarshalPKCS1PublicKey(pubkey)}))
    return pubkey_pem
}
func ExportPrivateKeyAsPemStr(privatekey *rsa.PrivateKey) string {
    privatekey_pem := string(pem.EncodeToMemory(&pem.Block{Type:  "RSA PRIVATE KEY",Bytes: x509.MarshalPKCS1PrivateKey(privatekey)}))
    return privatekey_pem
}
func ExportMsgAsPemStr(msg []byte) string {
    msg_pem := string(pem.EncodeToMemory(&pem.Block{Type:  "MESSAGE",Bytes: msg}))
    return msg_pem
}

func rsaConfigSetup(rsaPrivateKeyLocation, rsaPublicKeyLocation, rsaPrivateKeyPassword string) (*rsa.PrivateKey, error) {
	if rsaPrivateKeyLocation == "" {
		log.Fatal("No RSA Key given, generating temp one", nil)
		return GenRSA(4096)
	}

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		log.Fatal("No RSA private key found, generating temp one", nil)
		return GenRSA(4096)
	}

	privPem, _ := pem.Decode(priv)
	var privPemBytes []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		log.Fatal("RSA private key is of the wrong type", privPem.Type)
	}

	if rsaPrivateKeyPassword != "" {
		privPemBytes, err = x509.DecryptPEMBlock(privPem, []byte(rsaPrivateKeyPassword))
	} else {
		privPemBytes = privPem.Bytes
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			log.Fatal("Unable to parse RSA private key, generating a temp one");
			return GenRSA(4096)
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return GenRSA(4096)
	}

	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		return GenRSA(4096)
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		return GenRSA(4096)
	}
	if pubPem.Type != "RSA PUBLIC KEY" {
		return GenRSA(4096)
	}

	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		return GenRSA(4096)
	}

	var pubKey *rsa.PublicKey
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return GenRSA(4096)
	}

	privateKey.PublicKey = *pubKey

	return privateKey, nil
}

// GenRSA returns a new RSA key of bits length
func GenRSA(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	return key, err
}

func main() {

 // bits := 1024
 flag.Parse()
 args := flag.Args()

 m:=args[0]


 // bobPrivateKey, _ := rsa.GenerateKey(rand.Reader,bits)
 bobPrivateKey, _ := rsaConfigSetup("./id_rsa", "./id_rsa.pem", "")
 
 bobPublicKey := &bobPrivateKey.PublicKey

 fmt.Printf("%s\n",  ExportPrivateKeyAsPemStr(bobPrivateKey))

 fmt.Printf("%s\n", ExportPublicKeyAsPemStr(bobPublicKey))

 message := []byte(m)
 label := []byte("")
 hash := sha256.New()

 for i := 1; i < 20; i++ {
  ciphertext, _ := rsa.EncryptOAEP(hash, rand.Reader, bobPublicKey, message, label)

  fmt.Printf("%s\n",ExportMsgAsPemStr(ciphertext))

  plainText, _:= rsa.DecryptOAEP(hash, rand.Reader, bobPrivateKey, ciphertext, label)

  fmt.Printf("RSA decrypted to [%s]", plainText)
 }

}
