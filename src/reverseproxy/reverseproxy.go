package reverseproxy

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/sdc-wob-type-3/Vanguard-mTLS-safari/tls-reverse-proxy/config"
	"net/http"
	"net/http/httputil"
)

type ReverseProxy struct {
	server *http.Server
}

func (rp *ReverseProxy) Listen() error {
	return rp.server.ListenAndServeTLS("", "")
}

func New(c config.Config) *ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(c.Target)
	oDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		oDirector(req)
		req.Header.Add("x-mtls-subject", req.TLS.PeerCertificates[0].Subject.CommonName)
	}

	pool := x509.NewCertPool()
	pool.AddCert(&c.ClientCa)
	server := &http.Server{
		Addr:    ":" + c.Port,
		Handler: proxy,
		TLSConfig: &tls.Config{
			GetCertificate: c.Loader.GetCertificate,
			ClientAuth:     tls.RequireAndVerifyClientCert,
			ClientCAs:      pool,
			MinVersion:     tls.VersionTLS12,
		},
	}
	return &ReverseProxy{server: server}
}
