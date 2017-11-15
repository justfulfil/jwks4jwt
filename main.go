package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path"
)

func main() {
	certdir := flag.String("certdir", "", "The directory to look for certificates")

	flag.Parse()

	if *certdir == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	var certs_directory_path string

	if path.IsAbs(*certdir) {
		certs_directory_path = *certdir
	} else {
		current_directory, _ := os.Getwd()
		certs_directory_path = path.Join(current_directory, *certdir)
	}

	certs_directory, err := os.Open(certs_directory_path)

	if err != nil {
		fmt.Println("Could not open", certs_directory_path)
		os.Exit(1)
	}

	cert_files, err := certs_directory.Readdir(0)

	if err != nil {
		fmt.Println("Could not open directory", certs_directory_path)
		os.Exit(1)
	}

	key_set := JSONWebKeySet{}

	for _, cert_fileinfo := range cert_files {
		if string(cert_fileinfo.Name()[0]) == "." {
			continue
		}
		cert_file_path := path.Join(certs_directory_path, cert_fileinfo.Name())
		cert_file, err := os.Open(cert_file_path)

		if err != nil {
			fmt.Println("Could not open file", cert_file_path)
			os.Exit(1)
		}

		cert, err := createCertificate(cert_file)

		if err != nil {
			fmt.Println(cert_file_path, "is not a valid certificate")
			os.Exit(1)
		}

		fingerprint := getCertFingerprint(cert)

		rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)

		if ok != true {
			fmt.Println(cert_file_path, "is not an RSA certificate")
			os.Exit(1)
		}

		modulus := base64.URLEncoding.EncodeToString(rsaPublicKey.N.Bytes())
		exponent := base64.URLEncoding.EncodeToString(big.NewInt(int64(rsaPublicKey.E)).Bytes())

		key := JSONWebKey{
			Algorithm: "RS256",
			KeyType:   "RSA",
			KeyUse:    "sig",
			KeyOps: []string{
				"verify",
			},
			X509CertificateChain: []string{
				base64.StdEncoding.EncodeToString(cert.Raw),
			},
			KeyID:    fingerprint,
			Modulus:  modulus,
			Exponent: exponent,
		}

		key_set.Keys = append(key_set.Keys, key)
	}

	output, err := json.MarshalIndent(&key_set, "", "  ")

	if err != nil {
		fmt.Println("Error writing JSON")
		os.Exit(1)
	}

	fmt.Println(string(output))
}

func createCertificate(file *os.File) (*x509.Certificate, error) {
	fileinfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	cert_bytes := make([]byte, fileinfo.Size(), fileinfo.Size())
	if _, err = file.Read(cert_bytes); err != nil {
		return nil, err
	}

	asn1_pem_block, _ := pem.Decode(cert_bytes)
	if asn1_pem_block == nil {
		return nil, errors.New("Not a valid PEM certificate")
	}

	cert, err := x509.ParseCertificate(asn1_pem_block.Bytes)
	return cert, err
}

func getCertFingerprint(cert *x509.Certificate) string {
	shasum := sha1.Sum(cert.Raw)
	fingerprint := hex.EncodeToString(shasum[:])
	return fingerprint
}

type JSONWebKey struct {
	KeyType              string   `json:"kty"`
	KeyUse               string   `json:"use"`
	KeyOps               []string `json:"key_ops"`
	Algorithm            string   `json:"alg"`
	KeyID                string   `json:"kid"`
	X509CertificateChain []string `json:"x5c"`
	Exponent             string   `json:"e"`
	Modulus              string   `json:"n"`
}

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}
