package certificateloader

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"log"
	"sync"
	"time"
)

func New(ctx context.Context, sm *secretsmanager.SecretsManager, secret string, interval time.Duration) *Loader {
	l := &Loader{
		sm:       sm,
		secret:   secret,
		interval: interval,
	}

	if err := l.load(); err != nil {
		log.Printf("error when loading certificate: %v\n", err)
	}

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Println("stopping certificate refresh")
				return
			case <-t.C:
				if err := l.load(); err != nil {
					log.Printf("error when loading certificate: %v\n", err)
				}
			}
		}
	}()

	return l
}

type Loader struct {
	sm          *secretsmanager.SecretsManager
	secret      string
	certificate *tls.Certificate
	mutex       sync.RWMutex
	interval    time.Duration
}

func (l *Loader) load() error {
	value, err := l.sm.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(l.secret),
	})
	if err != nil {
		return err
	}

	var c certificate
	if err := json.Unmarshal([]byte(aws.StringValue(value.SecretString)), &c); err != nil {
		return err
	}

	cert, err := tls.X509KeyPair([]byte(c.Fullchain), []byte(c.PrivateKey))
	if err != nil {
		return err
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.certificate = &cert

	return nil
}

type certificate struct {
	PrivateKey  string `json:"private_key"`
	Fullchain   string `json:"fullchain"`
	Certificate string `json:"cert"`
}

func (l *Loader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.certificate, nil
}
