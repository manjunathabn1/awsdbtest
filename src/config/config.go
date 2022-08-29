package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/sdc-wob-type-3/Vanguard-mTLS-safari/tls-reverse-proxy/certificateloader"
	"net/url"
	"os"
	"time"
)

type GetCertificate interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

//go:embed ca/ca.pem
var caCertificate []byte

type Config struct {
	Port     string
	Loader   GetCertificate
	ClientCa x509.Certificate
	Target   *url.URL
}

func Init(ctx context.Context) (Config, error) {
	interval, present := os.LookupEnv("CERT_INTERVAL")
	if !present {
		return Config{}, errors.New("interval to refresh certificate missing, please provide CERT_INTERVAL")
	}
	intervalDuration, err := time.ParseDuration(interval)
	if err != nil {
		return Config{}, err
	}
	port, present := os.LookupEnv("PORT")
	if !present {
		return Config{}, errors.New("port is missing, please provide PORT")
	}
	t, present := os.LookupEnv("PROXY_TARGET")
	if !present {
		return Config{}, errors.New("reverse proxy target is missing, please provide PROXY_TARGET")
	}
	apiServerUrl, err := url.ParseRequestURI(t)
	if err != nil {
		return Config{}, err
	}
	domain, present := os.LookupEnv("DOMAIN")
	if !present {
		return Config{}, errors.New("reverse proxy domain is missing, please provide DOMAIN")
	}
	secret := domain + "/certificate"

	sess, err := session.NewSession(aws.NewConfig().WithRegion("eu-west-1"))
	if err != nil {
		return Config{}, err
	}

	cl := secretsmanager.New(sess)
	l := certificateloader.New(ctx, cl, secret, intervalDuration)

	block, _ := pem.Decode(caCertificate)
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return Config{
		Port:     port,
		Loader:   l,
		Target:   apiServerUrl,
		ClientCa: *cert,
	}, nil
}
