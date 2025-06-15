package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	// Load the certificate to verify
	certPEM, err := ioutil.ReadFile("leaf.crt")
	if err != nil {
		log.Fatal(err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		log.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Verifying cert for subject: %s\n", cert.Subject.CommonName)

	// Load the issuer's certificate
	issuerPEM, err := ioutil.ReadFile("issuer.crt")
	if err != nil {
		log.Fatal(err)
	}
	issuerBlock, _ := pem.Decode(issuerPEM)
	if issuerBlock == nil || issuerBlock.Type != "CERTIFICATE" {
		log.Fatal("failed to decode issuer PEM")
	}
	issuerCert, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	// Parse ASN.1 structure of the cert to get tbsCertificate and signature
	var full struct {
		TBSCert            asn1.RawValue
		SignatureAlgorithm asn1.RawValue
		SignatureValue     asn1.BitString
	}
	_, err = asn1.Unmarshal(certBlock.Bytes, &full)
	if err != nil {
		log.Fatalf("failed to parse ASN.1 cert structure: %v", err)
	}

	// Hash tbsCertificate with SHA-256
	tbsHash := sha256.Sum256(full.TBSCert.FullBytes)

	// Verify signature using issuer's public key
	switch pub := issuerCert.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, tbsHash[:], full.SignatureValue.Bytes)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, tbsHash[:], full.SignatureValue.Bytes) {
			err = fmt.Errorf("ECDSA signature verification failed")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, full.TBSCert.FullBytes, full.SignatureValue.Bytes) {
			err = fmt.Errorf("Ed25519 signature verification failed")
		}
	default:
		log.Fatalf("unsupported public key type: %T", pub)
	}

	if err != nil {
		log.Fatalf("signature verification failed: %v", err)
	}

	fmt.Println("✅ Signature is valid (verified against issuer's public key)")
}
