package main

import (
	enc "DistributedIBE/encryption"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	bls "github.com/drand/kyber-bls12381"
)

const EXPECTING_ARG_NUM = 4

func main() {
	if len(os.Args) != EXPECTING_ARG_NUM {
		panic(fmt.Sprintf("\nExpecting %d arguments, got %d arguments. Usage: ./encrypter <ID> <publickey> <plaintext>\n", EXPECTING_ARG_NUM, len(os.Args)))
	}

	suite := bls.NewBLS12381Suite()
	publicKeyByte, err := hex.DecodeString(os.Args[2])
	if err != nil {
		panic(fmt.Sprintf("\nError decoding public key: %s\n", err.Error()))
	}

	publicKeyPoint := suite.G1().Point()
	err = publicKeyPoint.UnmarshalBinary(publicKeyByte)
	if err != nil {
		panic(fmt.Sprintf("\nError unmarshalling public key: %s\n", err.Error()))
	}

	var destCipherData bytes.Buffer
	err = enc.Encrypt(publicKeyPoint, []byte(os.Args[2]), &destCipherData, bytes.NewBuffer([]byte(os.Args[3])))
	if err != nil {
		panic(fmt.Sprintf("\nError encrypting: %s\n", err.Error()))
	}

	fmt.Println(hex.EncodeToString(destCipherData.Bytes()))
}
