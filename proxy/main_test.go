package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tjamet/local-https-dev/server/acme"
)

func TestHandler(t *testing.T) {
	test := func(host, hostInURL, expectedProto, expectedHost string) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/something?a=3&b=4", r.URL.String())
			assert.Equal(t, expectedHost, r.Host)
			assert.Equal(t, []string{expectedProto}, r.Header["X-Forwarded-Proto"])
			assert.Equal(t, []string{"167.0.0.1"}, r.Header["X-Forwarded-For"])
			assert.Equal(t, []string{"_"}, r.Header["Test"])
			w.Header().Set("new", "value")
			w.WriteHeader(898)
			w.Write([]byte("body"))
		}))
		r := httptest.NewRequest("GET", host+"/something?a=3&b=4", nil)
		if hostInURL != "" {
			r.URL.Host = hostInURL
			r.URL.Scheme = expectedProto
		}
		r.Header.Set("test", "_")
		r.RemoteAddr = "167.0.0.1:1254"
		w := httptest.NewRecorder()
		u, err := url.Parse(s.URL)
		assert.NoError(t, err)
		newProxyHandler(http.DefaultClient, u).ServeHTTP(w, r)
		assert.Equal(t, []string{"value"}, w.Result().Header["New"])
		assert.Equal(t, "body", w.Body.String())
	}
	test("https://example.com", "example.com", "https", "example.com")
	test("http://example.com", "example.com", "http", "example.com")
	test("http://example.co", "", "http", "example.co")
}

func TestGetCertificate(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(3 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	assert.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	assert.NoError(t, err)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	assert.NoError(t, err)
	certBytes := bytes.NewBuffer(nil)
	keyBytes := bytes.NewBuffer(nil)
	pem.Encode(certBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(keyBytes, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := json.Marshal(acme.Certificate{
			Certificate: certBytes.Bytes(),
			PrivateKey:  keyBytes.Bytes(),
		})
		assert.NoError(t, err)
		w.Write(b)
	}))
	c, err := getCertificate(s.URL)
	assert.NoError(t, err)
	assert.NotNil(t, c)
}
