package c_token

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"hash"
)

var (
	ErrInvalidAlg    = errors.New("invalid alg")
	ErrInvalidPubKey = errors.New("invalid publicKey")
	ErrInvalidEnType = errors.New("invalid encrypt type")
	ErrInvalidPriKey = errors.New("invalid privateKey")
)

type EncryptType string

const (
	EncryptTypePKIX  EncryptType = "PKIX"
	EncryptTypePKCS1 EncryptType = "PKCS1"
	EncryptTypePKCS8 EncryptType = "PKCS8"

	DefaultPubEnType = EncryptTypePKIX
	DefaultPriEnType = EncryptTypePKCS1
)

type token struct {
	publicKey  string
	privateKey string
}

func NewToken() *token {
	publicKey, privateKey, _ := GenRsaKeyPair(1024, DefaultPubEnType, DefaultPriEnType)
	return &token{publicKey, privateKey}
}

func (t *token) GetPublicKey() string {
	return t.publicKey
}

func (t *token) GetPrivateKey() string {
	return t.privateKey
}

func (t *token) Encrypt(encryptMsg []byte) (string, error) {
	tokenByte, err := RsaEncrypt(encryptMsg, t.publicKey, DefaultPubEnType)
	return string(tokenByte), err
}

func (t *token) Decrypt(token string) (string, error) {
	deByte, err := RsaDecrypt([]byte(token), t.privateKey, DefaultPriEnType)
	return string(deByte), err
}

func (t *token) Sign(msg string) (enSign string, err error) {
	return Sign(msg, t.privateKey, DefaultPriEnType, crypto.SHA1)
}

func (t *token) VerfiySign(msg, signature string) (err error) {
	return VerfiySign(msg, signature, t.publicKey, DefaultPubEnType, crypto.SHA1)
}

/**
生成公钥和私钥
param bits 长度,一般为2048/1024
生成公钥,私钥(公钥加密,私钥解密|私钥签名,公钥验签)
bits 位数,一般为1024/2048
pubEnType 公钥加密算法 PKCS1 | PKIX
priEnType 私钥加密算法 PKCS1 | PKCS8
*/
func GenRsaKeyPair(bits int, pubEnType, priEnType EncryptType) (string, string, error) {
	privateKeyStr, publicKeyStr := "", ""

	//1.生成私钥
	//GenerateKey函数使用随机数据生成器random生成一对具有指定位数的RSA秘钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	//2.MarshalPKCS1PrivateKey 将rsa私钥序列化为ASN.1 PKCS#1 DER编码
	var derPrivateStream []byte
	switch priEnType {
	case EncryptTypePKCS1:
		derPrivateStream = x509.MarshalPKCS1PrivateKey(privateKey)
	case EncryptTypePKCS8:
		derPrivateStream, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return "", "", err
		}
	default:
		return "", "", ErrInvalidEnType
	}

	//3.Block代表PEM编码的结构,对其配置
	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derPrivateStream,
	}

	buf := bytes.NewBuffer(nil)

	//4.生成私钥
	err = pem.Encode(buf, &block)
	if err != nil {
		return "", "", err
	}
	privateKeyStr = buf.String()
	buf.Reset()

	//5.生成公钥
	var derPublicStream []byte
	publicKey := privateKey.PublicKey
	switch pubEnType {
	case EncryptTypePKCS1:
		derPublicStream = x509.MarshalPKCS1PublicKey(&publicKey)
	case EncryptTypePKIX:
		derPublicStream, err = x509.MarshalPKIXPublicKey(&publicKey)
		if err != nil {
			return "", "", err
		}
	default:
		return "", "", ErrInvalidEnType
	}

	block = pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPublicStream,
	}
	err = pem.Encode(buf, &block)
	if err != nil {
		return "", "", err
	}
	publicKeyStr = buf.String()

	return publicKeyStr, privateKeyStr, nil
}

/**
rsa 公钥加密,私钥解密
公钥加密
enMsg 需要加密的数据
pubEnType 公钥加密算法 PKCS1 | PKIX
enByte    加密后的数据
*/
func RsaEncrypt(enMsg []byte, publicKey string, pubEnType EncryptType) ([]byte, error) {
	pubKey, err := rsaParsePubKey(publicKey, pubEnType)
	if err != nil {
		return nil, err
	}

	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, enMsg)
	if err != nil {
		return nil, err
	}

	enByte := make([]byte, base64.StdEncoding.EncodedLen(len(encryptedBytes)))
	base64.StdEncoding.Encode(enByte, encryptedBytes)
	return enByte, nil
}

/**
私钥解密
deMsg 公钥加密后的数据
priEnType  私钥加密算法 PKCS1 | PKCS8
deByte     解密后的数据
*/
func RsaDecrypt(deMsg []byte, privateKey string, priEnType EncryptType) ([]byte, error) {
	deByte := make([]byte, base64.StdEncoding.EncodedLen(len(deMsg)))
	n, err := base64.StdEncoding.Decode(deByte, deMsg)
	if err != nil {
		return nil, err
	}

	priKey, err := rsaParsePriKey(privateKey, priEnType)
	if err != nil {
		return nil, err
	}

	decryptedStr, err := rsa.DecryptPKCS1v15(rand.Reader, priKey, deByte[:n])
	if err != nil {
		return nil, err
	}

	return decryptedStr, nil
}

/**
rsa 数字签名 私钥签名,公钥验签
私钥签名
msg 根据此消息生成签名
priEnType 私钥解密算法 PKCS1|PKCS8
alg 算法 sha1|sha256
*/
func Sign(msg string, privateKey string, priEnType EncryptType, alg crypto.Hash) (string, error) {
	var h hash.Hash

	switch alg {
	case crypto.SHA1:
		h = sha1.New()
	case crypto.SHA256:
		h = sha256.New()
	default:
		return "", ErrInvalidAlg
	}
	h.Write([]byte(msg))
	hashed := h.Sum(nil)

	rsaPrivateKey, err := rsaParsePriKey(privateKey, priEnType)
	if err != nil {
		return "", err
	}

	encryptedData, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, alg, hashed)
	if err != nil {
		return "", err
	}

	enSign := hex.EncodeToString(encryptedData)
	return enSign, nil
}

//公钥验签
//msg 根据此消息验证签名
//sig 签名信息
//pubEnType 公钥解析算法 PKIX|PKCS1
func VerfiySign(msg, signature string, publicKey string, pubEnType EncryptType, alg crypto.Hash) error {
	var h hash.Hash

	switch alg {
	case crypto.SHA1:
		h = sha1.New()
	case crypto.SHA256:
		h = sha256.New()
	default:
		return ErrInvalidAlg
	}
	h.Write([]byte(msg))
	hashed := h.Sum(nil)

	pub, err := rsaParsePubKey(publicKey, pubEnType)
	if err != nil {
		return err
	}

	sig, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(pub, alg, hashed, sig)
}

//公钥解析
//publicKey 公钥
//pubEnType 公钥解析算法 PKIX|PKCS1
func rsaParsePubKey(publicKey string, pubEnType EncryptType) (*rsa.PublicKey, error) {
	//1.从公钥中找出block和pubKey
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, ErrInvalidPubKey
	}

	switch pubEnType {
	case EncryptTypePKIX:
		pu, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		pubK, ok := pu.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key assign failed")
		}

		return pubK, nil
	case EncryptTypePKCS1:
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, ErrInvalidEnType
	}
}

//私钥解析
//privateKey 私钥
//priEnType 私钥解密算法 PKCS1|PKCS8
func rsaParsePriKey(privateKey string, priEnType EncryptType) (*rsa.PrivateKey, error) {
	//从私钥中找出block和priKey
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, ErrInvalidPriKey
	}

	switch priEnType {
	case EncryptTypePKCS1:
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case EncryptTypePKCS8:
		priKeyImpl, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		priKey, ok := priKeyImpl.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key assign failed")
		}

		return priKey, nil
	default:
		return nil, ErrInvalidEnType
	}
}
