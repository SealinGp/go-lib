package c_token

import (
	"log"
	"testing"
)

//
func TestNewToken(t *testing.T) {
	pubKey, priKey, err := RsaGenKeyPair(1024, "PKIX", "PKCS1")
	if err != nil {
		return
	}
	to := NewToken(pubKey, priKey)
	log.Printf("%v", pubKey)
	log.Printf("%v", priKey)

	msg := "123"
	ts, e := to.Encrypt([]byte(msg))
	if e != nil {
		t.Errorf("encrypt failed. err:%v", e)
		return
	}

	deStr, e := to.Decrypt(ts)
	if e != nil {
		t.Errorf("decrypt failed. err:%v", e)
		return
	}

	to.Sign(msg, "PKCS1", "sha1")

	t.Logf("[I] success str:%v", deStr)
}
