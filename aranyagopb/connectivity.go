package aranyagopb

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func (c *TLSConfig) GetTLSConfig() (_ *tls.Config, err error) {
	if c == nil {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify,
	}

	for _, c := range c.CipherSuites {
		tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, uint16(c))
	}

	if caBytes := c.CaCert; len(caBytes) != 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		block, _ := pem.Decode(caBytes)
		if block == nil {
			// not encoded in pem format
			var caCerts []*x509.Certificate
			caCerts, err = x509.ParseCertificates(caBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ca certs: %w", err)
			}
			for i := range caCerts {
				tlsConfig.RootCAs.AddCert(caCerts[i])
			}
		} else if !tlsConfig.RootCAs.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to add pem formated ca certs")
		}
	}

	if len(c.Key) != 0 && len(c.Cert) != 0 {
		cert, err := tls.X509KeyPair(c.Cert, c.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to create x509 pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}
