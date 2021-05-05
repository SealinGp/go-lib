package c_token

import (
	"log"
	"testing"
)

//
func TestNewToken(t *testing.T) {
	token := NewToken()
	log.Printf("%v", token.GetPublicKey())
	log.Printf("%v", token.GetPrivateKey())

	msg := "123"

	//public key encrypted
	ts, e := token.Encrypt([]byte(msg))
	if e != nil {
		t.Errorf("encrypt failed. err:%v", e)
		return
	}

	//private key decrypted
	deStr, e := token.Decrypt(ts)
	if e != nil {
		t.Errorf("decrypt failed. err:%v", e)
		return
	}

	//sign
	enSign, err := token.Sign(msg)
	if err != nil {
		log.Printf("[E] sign failed. err:%v", err)
		return
	}

	err = token.VerfiySign(msg, enSign)
	if err != nil {
		log.Printf("[E] verify sign failed. err:%v", err)
		return
	}

	t.Logf("[I] success str:%v", deStr)
}
