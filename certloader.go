package razproxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// CertLoader ...
type CertLoader interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

type genCertLoader tls.Certificate

// NewGeneratedCertLoader returns a CertLoader that supplies a generated certificate
func NewGeneratedCertLoader(name, org string) (CertLoader, error) {
	cert, err := generateCertificate(name, org)
	return (*genCertLoader)(cert), err
}

func (cert *genCertLoader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return (*tls.Certificate)(cert), nil
}

type fileCertLoader struct {
	certFile string
	keyFile  string
	cert     atomic.Value
	logger   *log.Logger
}

// NewFileCertLoader returns a CertLoader that reads a certificate file and watches for updates
func NewFileCertLoader(certFile, keyFile string, logger *log.Logger) (CertLoader, error) {
	loader := &fileCertLoader{
		certFile: certFile,
		keyFile:  keyFile,
		logger:   logger,
	}
	if err := loader.load(); err != nil {
		return nil, err
	}
	go loader.watch()
	return loader, nil
}

func (loader *fileCertLoader) load() error {
	if len(loader.keyFile) > 0 {
		cert, err := tls.LoadX509KeyPair(loader.certFile, loader.keyFile)
		if err != nil {
			return err
		}
		loader.cert.Store(&cert)
		return nil
	}
	cert, err := loadCertficateAndKeyFromFile(loader.certFile)
	if err != nil {
		return err
	}
	loader.cert.Store(cert)
	return nil
}

func (loader *fileCertLoader) watch() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		loader.logger.Println(err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(loader.certFile); err != nil {
		loader.logger.Println(err)
		return
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				if err := loader.load(); err != nil {
					loader.logger.Println(err)
				} else {
					loader.logger.Println("Certificate reloaded")
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			loader.logger.Println(err)
		}
	}
}

func (loader *fileCertLoader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return loader.cert.Load().(*tls.Certificate), nil
}

func generateCertificate(name, org string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Generate a pem block with the private key
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tml := x509.Certificate{
		// you can add any attr that you need
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(5, 0, 0),
		// you have to generate a different serial number each execution
		SerialNumber: big.NewInt(123123),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{org},
		},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	// Generate a pem block with the certificate
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	c, err := tls.X509KeyPair(certPem, keyPem)
	return &c, err
}

func loadCertficateAndKeyFromFile(path string) (*tls.Certificate, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cert tls.Certificate
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} else {
			cert.PrivateKey, err = parsePrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("Failure reading private key from \"%s\": %s", path, err)
			}
		}
		raw = rest
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("No certificate found in \"%s\"", path)
	} else if cert.PrivateKey == nil {
		return nil, fmt.Errorf("No private key found in \"%s\"", path)
	}

	return &cert, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("Failed to parse private key")
}
