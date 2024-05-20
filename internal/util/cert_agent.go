package util

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type CertificateStatus struct {
	Path       string    `json:"path"`
	NotAfter   time.Time `json:"not_after"`
	NodeName   string    `json:"node_name"`
	IsExpiring bool      `json:"is_expiring"`
}

func checkCertificate(path string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func StartAgent() {
	nodeName := os.Getenv("NODE_NAME")
	certPaths := []string{"/etc/ssl/certs/mycert.pem", "/etc/ssl/certs/anothercert.pem"}

	statuses := []CertificateStatus{}

	for _, path := range certPaths {
		cert, err := checkCertificate(path)
		status := CertificateStatus{
			Path:     path,
			NodeName: nodeName,
		}
		if err != nil {
			status.NotAfter = time.Time{}
			status.IsExpiring = false
		} else {
			status.NotAfter = cert.NotAfter
			status.IsExpiring = time.Until(cert.NotAfter) < 30*24*time.Hour
		}
		statuses = append(statuses, status)
	}

	data, err := json.Marshal(statuses)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}

	_, err = http.Post("http://your-operator-service/cert-status", "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("EEEEError sending data to operator: %v\n", err)
	}
}
