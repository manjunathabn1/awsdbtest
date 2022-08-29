package reverseproxy_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"github.com/sdc-wob-type-3/Vanguard-mTLS-safari/tls-reverse-proxy/config"
	"github.com/sdc-wob-type-3/Vanguard-mTLS-safari/tls-reverse-proxy/reverseproxy"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"
)

type GetCertificateFake struct {
	cert tls.Certificate
}

const endpoint = "/actuator/health"

var _ = Describe("Reverseproxy", func() {
	var server *ghttp.Server

	BeforeEach(func() {
		server = ghttp.NewServer()
		server.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest(http.MethodGet, endpoint),
				ghttp.VerifyHeaderKV("x-mtls-subject", "aCommonName"),
				ghttp.RespondWith(http.StatusCreated, aBody()),
			),
		)
	})

	AfterEach(func() {
		server.Close()
	})

	It("works on correct client certificate", func() {
		serverCert := generateServerCertificate("localhost")
		rootCa, clientCertfromRootCa := generateCaWithClientCertificate("aCommonName")
		c := config.Config{
			Port:     "8080",
			Loader:   GetCertificateFake{cert: serverCert},
			ClientCa: *rootCa,
			Target:   server.URL(),
		}

		startInBackground(reverseproxy.New(c))
		trusting := anHttpClientWithCertificateTrusting(clientCertfromRootCa, serverCert)
		resp, err := trusting.Get("https://localhost:8080" + endpoint)

		Expect(err).NotTo(HaveOccurred())
		Expect(server.ReceivedRequests()).Should(HaveLen(1))
		Expect(resp.StatusCode).To(Equal(http.StatusCreated))
		Expect(readBody(resp.Body)).To(Equal(aBody()))
	})

	It("fails on client certificate from not trusted root ca", func() {
		serverCert := generateServerCertificate("localhost")
		trustedRootCa, _ := generateCaWithClientCertificate("aCommonName")
		_, clientCertFromUntrustedRootCa := generateCaWithClientCertificate("aCommonName")
		c := config.Config{
			Port:     "8082",
			Loader:   GetCertificateFake{cert: serverCert},
			ClientCa: *trustedRootCa,
			Target:   server.URL(),
		}

		startInBackground(reverseproxy.New(c))
		trusting := anHttpClientWithCertificateTrusting(clientCertFromUntrustedRootCa, serverCert)
		_, err := trusting.Get("https://localhost:8082" + endpoint)

		Expect(server.ReceivedRequests()).Should(HaveLen(0))
		Expect(err).To(HaveOccurred())
	})

	It("fails with missing client certificate", func() {
		serverCert := generateServerCertificate("localhost")
		_, clientCert := generateCaWithClientCertificate("aCommonName")
		c := config.Config{
			Port:     "8081",
			Loader:   GetCertificateFake{cert: serverCert},
			ClientCa: *toX509(clientCert),
			Target:   server.URL(),
		}

		startInBackground(reverseproxy.New(c))
		_, err := anHttpClientTrusting(serverCert).Get("https://localhost:8081" + endpoint)

		Expect(server.ReceivedRequests()).Should(HaveLen(0))
		Expect(err).To(HaveOccurred())
	})
})

func aBody() []byte {
	return []byte("asdf")
}

func readBody(readCloser io.ReadCloser) []byte {
	defer func() { _ = readCloser.Close() }()
	d, err := ioutil.ReadAll(readCloser)
	Expect(err).NotTo(HaveOccurred())
	return d
}

func startInBackground(rp *reverseproxy.ReverseProxy) {
	go func() {
		err := rp.Listen()
		if err != nil {
			Fail("server did not start")
		}
	}()
}

func anHttpClientTrusting(cert tls.Certificate) *http.Client {
	certPool := x509.NewCertPool()
	certPool.AddCert(toX509(cert))
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}
}

func anHttpClientWithCertificateTrusting(client tls.Certificate, server tls.Certificate) *http.Client {
	certPool := x509.NewCertPool()
	certPool.AddCert(toX509(server))
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
				Certificates: []tls.Certificate{
					client,
				},
			},
		},
	}
}

func toX509(cert tls.Certificate) *x509.Certificate {
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	Expect(err).NotTo(HaveOccurred())
	return x509Cert
}

func generateServerCertificate(domain string) tls.Certificate {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	publickey := &privatekey.PublicKey

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   "aCommonName",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publickey, privatekey)
	Expect(err).NotTo(HaveOccurred())
	out := &bytes.Buffer{}
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	Expect(err).NotTo(HaveOccurred())
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
		},
	)
	Expect(err).NotTo(HaveOccurred())
	c, err := tls.X509KeyPair(out.Bytes(), pemdata)
	Expect(err).NotTo(HaveOccurred())
	return c
}

func generateCaWithClientCertificate(commonName string) (*x509.Certificate, tls.Certificate) {
	caCert, caKeyPair := GenCARoot()
	return caCert, clientKeyPair(commonName, caCert, caKeyPair)
}

func clientKeyPair(commonName string, caCert *x509.Certificate, caPrivteKey *rsa.PrivateKey) tls.Certificate {
	clientPrivateKey := rsaKeyPair()
	clientCert := genCert(&x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}, caCert, &clientPrivateKey.PublicKey, caPrivteKey)

	return toTlsCertificate(clientPrivateKey, clientCert)
}

func toTlsCertificate(privateKey *rsa.PrivateKey, cert *x509.Certificate) tls.Certificate {
	result, err := tls.X509KeyPair(certToPem(cert), keyToPem(privateKey))
	Expect(err).NotTo(HaveOccurred())
	return result
}

func keyToPem(privateKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
}

func certToPem(cert *x509.Certificate) []byte {
	certPemBlock := &bytes.Buffer{}
	Expect(pem.Encode(certPemBlock, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})).NotTo(HaveOccurred())
	i := certPemBlock.Bytes()
	return i
}

func genCert(template, parent *x509.Certificate, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *x509.Certificate {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	Expect(err).NotTo(HaveOccurred())

	cert, err := x509.ParseCertificate(certBytes)
	Expect(err).NotTo(HaveOccurred())

	return cert
}

func GenCARoot() (*x509.Certificate, *rsa.PrivateKey) {
	keyPair := rsaKeyPair()
	var rootTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Company Co."},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	cert := genCert(&rootTemplate, &rootTemplate, &keyPair.PublicKey, keyPair)
	return cert, keyPair
}

func rsaKeyPair() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	return key
}

func (g GetCertificateFake) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &g.cert, nil
}
