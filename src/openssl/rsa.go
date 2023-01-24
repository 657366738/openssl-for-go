package openssl

// #include "shim.h"
import "C"
import (
	"bytes"
	"encoding/hex"
	"unsafe"
)

var RSA_PKCS1_PADDING = C.int(1)

func Rsa_PublicEnc(e, n string, in []byte) []byte {
	rsa := C.RSA_new()
	var strOut []byte
	ke := C.CString(e)
	kn := C.CString(n)

	if C.X_BN_hex2bn_E(rsa, ke) == 0 {
		C.free(unsafe.Pointer(ke))
		C.free(unsafe.Pointer(kn))
		C.RSA_free(rsa)
		return nil
	}
	if C.X_BN_hex2bn_N(rsa, kn) == 0 {
		C.free(unsafe.Pointer(ke))
		C.free(unsafe.Pointer(kn))
		C.RSA_free(rsa)
		return nil
	}
	rsa_len := int(C.RSA_size(rsa))
	if len(in) >= rsa_len-12 {
		blockCnt := (len(in) / (rsa_len - 12)) + 0
		if len(in)%(rsa_len-12) == 0 {

		} else {
			blockCnt = (len(in) / (rsa_len - 12)) + 1
		}
		strOut = make([]byte, 0)
		tempin := bytes.NewBuffer(in)
		for i := 0; i < blockCnt; i++ {
			blckSize := rsa_len - 12
			if i == blockCnt-1 {
				blckSize = len(in) - (i * blckSize)
			}
			//privateKey_ := (*C.uchar)(&(privateKey[:1][0]))
			tempin1 := tempin.ReadBytesN(int(C.int(blckSize)))
			tempot := make([]byte, C.int(rsa_len))

			if C.RSA_public_encrypt(C.int(blckSize), (*C.uchar)(&(tempin1[:1][0])), (*C.uchar)(&(tempot[:1][0])), rsa, RSA_PKCS1_PADDING) < 0 {
				tempot = nil
			}
			strOut = append(strOut, tempot...)

		}

	} else {
		strOut = make([]byte, rsa_len)
		if C.RSA_public_encrypt(C.int(len(in)), (*C.uchar)(&(in[:1][0])), (*C.uchar)(&(strOut[:1][0])), rsa, RSA_PKCS1_PADDING) < 0 {
			strOut = nil
		}
	}

	C.free(unsafe.Pointer(ke))
	C.free(unsafe.Pointer(kn))
	C.RSA_free(rsa)
	return strOut
}
func X_PEM_read_bio_RSAPublicKey(Key []byte) {
	signature := make([]byte, 1024)
	signature_ := (*C.uchar)(&(signature[:1][0]))
	rsa := C.RSA_new()
	priKey := unsafe.Pointer(&(Key[:1][0]))
	keybio := C.BIO_new_mem_buf(priKey, -1)
	rsa = C.X_PEM_read_bio_RSAPublicKey(keybio, &rsa)

	oul := C.X_BN_bn2bin_N(rsa, signature_)
	println(hex.EncodeToString(bytes.NewBuffer(signature).ReadBytesN(int(oul))))
	C.X_BN_bn2bin_E(rsa, signature_)
}

//X_BN_bn2bin_N
func Rsa_PrivateDec(Key, cipherText []byte) []byte {
	rsa := C.RSA_new()
	priKey := unsafe.Pointer(&(Key[:1][0]))
	keybio := C.BIO_new_mem_buf(priKey, -1)
	rsa = C.X_PEM_read_bio_RSAPrivateKey(keybio, &rsa)
	rsa_len := int(C.RSA_size(rsa))
	cipher := bytes.NewBuffer(cipherText)
	if len(cipherText) > rsa_len {
		decryptedText := make([]byte, 0)
		for i := 0; i < len(cipherText)/rsa_len; i++ {
			tempin := cipher.ReadBytesN((rsa_len))
			tempot := make([]byte, (rsa_len))
			ilen := C.RSA_private_decrypt(C.int(rsa_len), (*C.uchar)(&(tempin[:1][0])), (*C.uchar)(&(tempot[:1][0])), rsa, RSA_PKCS1_PADDING)
			if ilen < 0 {
				decryptedText = nil

			}

			decryptedText = append(decryptedText, bytes.NewBuffer(tempot).ReadBytesN(int(ilen))...)
		}

		C.BIO_free_all(keybio)
		C.RSA_free(rsa)
		return decryptedText
	} else {
		decryptedText := make([]byte, rsa_len)
		ret := C.RSA_private_decrypt(C.int(len(cipherText)), (*C.uchar)(&(cipherText[:1][0])), (*C.uchar)(&(decryptedText[:1][0])), rsa, RSA_PKCS1_PADDING)
		if ret > 0 {

			//C.free(unsafe.Pointer(priKey))
			C.BIO_free_all(keybio)
			C.RSA_free(rsa)
			return decryptedText[0:int(ret)]
		}
	}

	//C.free(unsafe.Pointer(priKey))
	C.BIO_free_all(keybio)
	C.RSA_free(rsa)
	return nil
}
