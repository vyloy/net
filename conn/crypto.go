package conn

import (
	"crypto/aes"
	cipher2 "crypto/cipher"
	"crypto/des"
	"crypto/sha512"
	"github.com/skycoin/skycoin/src/cipher"
	"io"
	"sync"
)

type Crypto struct {
	es      cipher2.Stream
	esMutex sync.Mutex
	ds      cipher2.Stream
	dsMutex sync.Mutex

	// header
	headerCipher cipher2.Block
}

func NewCrypto(secKey cipher.SecKey, target cipher.PubKey, iv []byte) *Crypto {
	ecdh := cipher.ECDH(target, secKey)
	b, err := aes.NewCipher(ecdh)
	if err != nil {
		return nil
	}
	s1 := sha512.Sum512(append(iv, ecdh...))
	s2 := sha512.Sum512(append(ecdh, iv...))
	s3 := sha512.Sum512(append(iv, s2[:]...))
	s4 := sha512.Sum512(append(ecdh, s1[:]...))
	sum := append(s2[:], s1[:]...)
	sum = append(sum, s3[:]...)
	sum = append(sum, s4[:]...)
	key := sha512.Sum512(sum)
	crypto := &Crypto{
		es: cipher2.NewCFBEncrypter(b, iv),
		ds: cipher2.NewCFBDecrypter(b, iv),
	}
	crypto.headerCipher, err = des.NewTripleDESCipher(key[:24])
	if err != nil {
		return nil
	}
	return crypto
}

func (c *Crypto) Encrypt(data []byte) {
	c.esMutex.Lock()
	c.es.XORKeyStream(data, data)
	c.esMutex.Unlock()
}

func (c *Crypto) Decrypt(data []byte) {
	c.dsMutex.Lock()
	c.ds.XORKeyStream(data, data)
	c.dsMutex.Unlock()
}

func (c *Crypto) EncryptBlock(data []byte) {
	c.headerCipher.Encrypt(data, data)
}

func (c *Crypto) DecryptBlock(data []byte) {
	c.headerCipher.Decrypt(data, data)
}

type CryptoGetter interface {
	GetCrypto() *Crypto
}

type CryptoReader struct {
	rd io.Reader
	cg CryptoGetter
}

func NewCryptoReader(rd io.Reader, getter CryptoGetter) *CryptoReader {
	return &CryptoReader{
		rd: rd,
		cg: getter,
	}
}

func (cr *CryptoReader) Read(p []byte) (n int, err error) {
	n, err = cr.rd.Read(p)
	if err != nil || n == 0 {
		return
	}
	crypto := cr.cg.GetCrypto()
	if crypto == nil {
		return
	}
	crypto.Decrypt(p[:n])
	return
}
