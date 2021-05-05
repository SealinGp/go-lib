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
	"strings"
)

type token struct {
	publicKey  string
	privateKey string
}

func NewToken(publicKey, privateKey string) *token {
	return &token{publicKey, privateKey}
}

var (
	PubKeyRequired = errors.New("publicKey required")
	PriKeyRequired = errors.New("privateKey required")
)

/**
生成token
encryptMsg 需要加密的数据
token 公钥加密后的数据
Err 错误信息
*/
func (t *token) Encrypt(encryptMsg []byte) (token string, Err error) {
	if t.publicKey == "" {
		Err = PubKeyRequired
		return
	}
	tokenByte, err := t.rsaEncrypt(encryptMsg, "PKIX")
	if err != nil {
		Err = err
		return
	}
	token = string(tokenByte)
	return
}

/**
解密token
*/
func (t *token) Decrypt(token string) (deStr string, Err error) {
	if t.privateKey == "" {
		Err = PriKeyRequired
		return
	}

	deByte, err := t.rsaDecrypt([]byte(token), "PKCS1")
	if err != nil {
		Err = err
		return
	}
	deStr = string(deByte)
	return
}

/**
生成公钥和私钥
param bits 长度,一般为2048/1024
*/

//生成公钥,私钥(公钥加密,私钥解密|私钥签名,公钥验签)
//bits 位数,一般为1024/2048
//PubEnType 公钥加密算法 PKCS1 | PKIX
//PriEnType 私钥加密算法 PKCS1 | PKCS8
func RsaGenKeyPair(bits int, PubEnType string, PriEnType string) (string, string, error) {
	privateKeyStr, publicKeyStr := "", ""
	//1.生成私钥
	//GenerateKey函数使用随机数据生成器random生成一对具有指定位数的RSA秘钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	//2.MarshalPKCS1PrivateKey 将rsa私钥序列化为ASN.1 PKCS#1 DER编码
	var derPrivateStream []byte
	if PriEnType == "PKCS1" {
		derPrivateStream = x509.MarshalPKCS1PrivateKey(privateKey)
	}
	if PriEnType == "PKCS8" {
		derPrivateStream, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return "", "", err
		}
	}
	if derPrivateStream == nil {
		return "", "", errors.New("privateKe enType:PKCS1 | PKCS8")
	}

	//3.Block代表PEM编码的结构,对其配置
	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derPrivateStream,
	}
	//4.写入缓冲中
	buffPrivate := &bytes.Buffer{}
	err = pem.Encode(buffPrivate, &block)
	if err != nil {
		return "", "", err
	}
	privateKeyStr = buffPrivate.String()

	//5.生成公钥
	var derPublicStream []byte
	publicKey := privateKey.PublicKey
	if PubEnType == "PKCS1" {
		derPublicStream = x509.MarshalPKCS1PublicKey(&publicKey)
	}
	if PubEnType == "PKIX" {
		derPublicStream, err = x509.MarshalPKIXPublicKey(&publicKey)
		if err != nil {
			return "", "", err
		}
	}
	if derPublicStream == nil {
		return "", "", errors.New("PublicKey enType:PKCS1 | PKIX")
	}
	block = pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPublicStream,
	}
	buffPublic := &bytes.Buffer{}
	err = pem.Encode(buffPublic, &block)
	if err != nil {
		return "", "", err
	}
	publicKeyStr = buffPublic.String()

	return publicKeyStr, privateKeyStr, nil
}

/*
* rsa 公钥加密,私钥解密
 */
//公钥加密
//enMsg 需要加密的数据
//PubEnType 公钥加密算法 PKCS1 | PKIX
//enByte    加密后的数据
func (t *token) rsaEncrypt(enMsg []byte, PubEnType string) (enByte []byte, Err error) {
	if t.publicKey == "" {
		Err = errors.New("PubKey required")
		return
	}

	//1.从公钥中找出block和pubKey
	pubKey, err := rsaParsePubKey(t.publicKey, PubEnType)
	if err != nil {
		Err = err
		return
	}

	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, enMsg)
	if err != nil {
		Err = err
		return
	}
	encryptedStr := base64.StdEncoding.EncodeToString(encryptedBytes)
	enByte = []byte(encryptedStr)
	return
}

//私钥解密
//deMsg 公钥加密后的数据
//PriEnType  私钥加密算法 PKCS1 | PKCS8
//deByte     解密后的数据
func (t *token) rsaDecrypt(deMsg []byte, PriEnType string) (deByte []byte, Err error) {
	if t.privateKey == "" {
		Err = errors.New("PriKey required")
		return
	}

	dst, err := base64.StdEncoding.DecodeString(string(deMsg))
	if err == nil {
		deMsg = dst
	}

	priKey, err := rsaParsePriKey(t.privateKey, PriEnType)
	if err != nil {
		Err = err
		return
	}
	decryptedStr, err := rsa.DecryptPKCS1v15(rand.Reader, priKey, deMsg)
	if err != nil {
		Err = err
		return
	}
	deByte = decryptedStr
	return
}

/*
* rsa 数字签名 私钥签名,公钥验签
 */
//私钥签名
//msg 根据此消息生成签名
//PriEnType 私钥解密算法 PKCS1|PKCS8
//alg 算法 sha1|sha256
func (t *token) Sign(msg, PriEnType, alg string) (enSign string, Err error) {
	if t.privateKey == "" {
		Err = errors.New("PriKey required")
		return
	}
	var hash1 hash.Hash
	var algr crypto.Hash
	switch strings.ToLower(alg) {
	case "sha1":
		hash1 = sha1.New()
		algr = crypto.SHA1
	case "sha256":
		hash1 = sha256.New()
		algr = crypto.SHA256
	default:
		Err = errors.New("alg error")
		return
	}

	priv, err := rsaParsePriKey(t.privateKey, PriEnType)
	if err != nil {
		Err = err
		return
	}

	hash1.Write([]byte(msg))
	encryptedData, err := rsa.SignPKCS1v15(rand.Reader, priv, algr, hash1.Sum(nil))
	if err != nil {
		Err = err
		return
	}

	enSign = hex.EncodeToString(encryptedData)
	return
}

//公钥验签
//msg 根据此消息验证签名
//sig 签名信息
//pubEnType 公钥解析算法 PKIX|PKCS1
func (t *token) VerfiySign(msg, signature, pubEnType, alg string) (Err error) {
	if t.publicKey == "" {
		Err = errors.New("PriKey required")
		return
	}
	var hash1 hash.Hash
	var algr crypto.Hash
	switch strings.ToLower(alg) {
	case "sha1":
		hash1 = sha1.New()
		algr = crypto.SHA1
	case "sha256":
		hash1 = sha256.New()
		algr = crypto.SHA256
	default:
		Err = errors.New("alg error")
		return
	}

	pub, err := rsaParsePubKey(t.publicKey, pubEnType)
	if err != nil {
		Err = err
		return
	}

	var sig1 []byte
	sig1, err = hex.DecodeString(signature)
	if err != nil {
		Err = err
		return
	}
	hash1.Write([]byte(msg))
	return rsa.VerifyPKCS1v15(pub, algr, hash1.Sum(nil), sig1)
}

//公钥解析
//publicKey 公钥
//pubEnType 公钥解析算法 PKIX|PKCS1
func rsaParsePubKey(publicKey string, pubEnType string) (Pub *rsa.PublicKey, Err error) {
	//1.从公钥中找出block和pubKey
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		Err = errors.New("error publicKey")
		return
	}

	if pubEnType == "PKIX" {
		pu, err := x509.ParsePKIXPublicKey(block.Bytes)
		PubK, ok := pu.(*rsa.PublicKey)
		if !ok {
			Err = errors.New("publick Key parse errors")
			return
		}
		Pub = PubK
		Err = err
		return
	}
	if pubEnType == "PKCS1" {
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}
	Err = errors.New("error enType")
	return
}

//私钥解析
//privateKey 私钥
//PriEnType 私钥解密算法 PKCS1|PKCS8
func rsaParsePriKey(privateKey string, priEnType string) (PriKey *rsa.PrivateKey, Err error) {
	//从私钥中找出block和priKey
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		Err = errors.New("error privateKey")
		return
	}
	if priEnType == "PKCS1" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if priEnType == "PKCS8" {
		PriKey1, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		PriKey = PriKey1.(*rsa.PrivateKey)
		Err = err
		return
	}
	Err = errors.New("PriEnType error")
	return
}
