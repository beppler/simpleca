package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func main() {
	app := cli.NewApp()
	app.Name = "simpleca"
	app.Usage = "Simple Certificate Authority"
	app.Version = "0.6.0"
	app.Commands = []cli.Command{
		{
			Name:  "ca",
			Usage: "Create a certificate authority certificate",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key",
					Usage: "RSA private key file `NAME`",
				},
				cli.StringFlag{
					Name:  "password",
					Usage: "private key `PASSWORD`",
				},
				cli.StringFlag{
					Name:  "country",
					Usage: "Country code for certificate request (ex. US)",
				},
				cli.StringFlag{
					Name:  "organization",
					Usage: "Organization name for certificate",
					Value: "ACME Development Certificate Authority",
				},
				cli.IntFlag{
					Name:  "validity",
					Usage: "Validity time in `YEARS`",
					Value: 10,
				},
				cli.StringFlag{
					Name:  "out",
					Usage: "Certificate authority certificate output file `NAME`",
				},
			},
			Action: genCA,
		},
		{
			Name:  "csr",
			Usage: "Create a certificate request",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key",
					Usage: "RSA private key file `NAME`",
				},
				cli.StringFlag{
					Name:  "password",
					Usage: "private key password",
				},
				cli.StringFlag{
					Name:  "country",
					Usage: "Country code (ex. US) for certificate request",
				},
				cli.StringFlag{
					Name:  "province",
					Usage: "Province (ex. California) for certificate request",
				},
				cli.StringFlag{
					Name:  "locality",
					Usage: "Locality (ex. Los Angeles) for certificate request",
				},
				cli.StringFlag{
					Name:  "organization",
					Usage: "Organization for certificate request",
				},
				cli.StringFlag{
					Name:  "unit",
					Usage: "Organizational unit for certificate request",
				},
				cli.StringFlag{
					Name:  "cn",
					Usage: "Common name for certificate request",
				},
				cli.StringSliceFlag{
					Name:  "dns",
					Usage: "Alternative host name for certificate request",
				},
				cli.StringSliceFlag{
					Name:  "ip",
					Usage: "Alternative IP address for certificate request",
				},
				cli.StringSliceFlag{
					Name:  "email",
					Usage: "Alternative RFC822 email address for certificate request",
				},
				cli.StringFlag{
					Name:  "out",
					Usage: "Certificate request output file `NAME`",
				},
			},
			Action: genCSR,
		},
		{
			Name:  "crl",
			Usage: "Create a certificate revogation list (CRL)",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "ca-cert",
					Usage: "Certificate authority certificate file `NAME`",
				},
				cli.StringFlag{
					Name:  "ca-key",
					Usage: "Certificare authority RSA private key file `NAME`",
				},
				cli.StringFlag{
					Name:  "ca-password",
					Usage: "private key password",
				},
				cli.IntFlag{
					Name:  "validity",
					Usage: "Validity time in `days` (0 to copy certificate authority validity)",
					Value: 7,
				},
				cli.StringSliceFlag{
					Name:  "cert",
					Usage: "Certificate to be included on CRL",
				},
				cli.StringFlag{
					Name:  "out",
					Usage: "Certificate revogation list output file `NAME`",
				},
			},
			Action: genCRL,
		},
		{
			Name:  "key",
			Usage: "Create a RSA private key",
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "size",
					Usage: "private key `SIZE` (in bits)",
					Value: 2048,
				},
				cli.StringFlag{
					Name:  "password",
					Usage: "private key `PASSWORD`",
				},
				cli.StringFlag{
					Name:  "out",
					Usage: "RSA private key output file `NAME`",
				},
			},
			Action: genKey,
		},
		{
			Name:  "pkcs",
			Usage: "PCKS12 support",
			Subcommands: []cli.Command{
				{
					Name:  "encode",
					Usage: "Encode a PKCS12 file from certificate and private key",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "cert",
							Usage: "Certificate file `NAME`",
						},
						cli.StringFlag{
							Name:  "key",
							Usage: "Private key file `NAME`",
						},
						cli.StringFlag{
							Name:  "password",
							Usage: "Private key `PASSWORD`",
						},
						cli.StringSliceFlag{
							Name:  "ca-cert",
							Usage: "Certificate authorities certificate file `NAME`",
						},
						cli.StringFlag{
							Name:  "out",
							Usage: "PKCS12 output file `NAME`",
						},
					},
					Action: genPkcs,
				},
			},
		},
		{
			Name:  "sign",
			Usage: "Sign a certificate request",
			Subcommands: []cli.Command{
				{
					Name:  "ca",
					Usage: "Sign a subordinate certificate authority request",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "csr",
							Usage: "Certificate request file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-cert",
							Usage: "Certificate authority certificate file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-key",
							Usage: "Certificare authority RSA private key file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-password",
							Usage: "private key `PASSWORD`",
						},
						cli.StringSliceFlag{
							Name:  "crl",
							Usage: "CRL distribution points `URI` for certificate",
						},
						cli.StringSliceFlag{
							Name:  "ocsp",
							Usage: "OCSP servers `URI` for certificate",
						},
						cli.IntFlag{
							Name:  "max-path-len",
							Usage: "Maximum number of subordinate CAs",
							Value: 0,
						},
						cli.IntFlag{
							Name:  "validity",
							Usage: "Validity time in `YEARS`",
							Value: 5,
						},
						cli.StringFlag{
							Name:  "out",
							Usage: "Server certificate output file `NAME`",
						},
					},
					Action: signCA,
				},
				{
					Name:  "code",
					Usage: "Sign a code signing certificate request",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "csr",
							Usage: "Certificate request file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-cert",
							Usage: "Certificate authority certificate file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-key",
							Usage: "Certificare authority RSA private key file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-password",
							Usage: "private key `PASSWORD`",
						},
						cli.StringSliceFlag{
							Name:  "crl",
							Usage: "CRL distribution points `URI` for certificate",
						},
						cli.StringSliceFlag{
							Name:  "ocsp",
							Usage: "OCSP servers `URI` for certificate",
						},
						cli.IntFlag{
							Name:  "validity",
							Usage: "Validity time in `YEARS`",
							Value: 2,
						},
						cli.StringFlag{
							Name:  "out",
							Usage: "Server certificate output file `NAME`",
						},
					},
					Action: signCode,
				},
				{
					Name:  "server",
					Usage: "Sign a server certificate request",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "csr",
							Usage: "Certificate request file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-cert",
							Usage: "Certificate authority certificate file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-key",
							Usage: "Certificare authority RSA private key file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-password",
							Usage: "private key `PASSWORD`",
						},
						cli.StringSliceFlag{
							Name:  "crl",
							Usage: "CRL distribution points `URI` for certificate",
						},
						cli.StringSliceFlag{
							Name:  "ocsp",
							Usage: "OCSP servers `URI` for certificate",
						},
						cli.IntFlag{
							Name:  "validity",
							Usage: "Validity time in `YEARS`",
							Value: 2,
						},
						cli.StringFlag{
							Name:  "out",
							Usage: "Server certificate output file `NAME`",
						},
					},
					Action: signServer,
				},
				{
					Name:  "user",
					Usage: "Sign a user certificate request",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "csr",
							Usage: "Certificate request file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-cert",
							Usage: "Certificate authority certificate file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-key",
							Usage: "Certificare authority RSA private key file `NAME`",
						},
						cli.StringFlag{
							Name:  "ca-password",
							Usage: "private key `PASSWORD`",
						},
						cli.StringSliceFlag{
							Name:  "crl",
							Usage: "CRL distribution points `URI` for certificate",
						},
						cli.StringSliceFlag{
							Name:  "ocsp",
							Usage: "OCSP servers `URI` for certificate",
						},
						cli.IntFlag{
							Name:  "validity",
							Usage: "Validity time in `YEARS`",
							Value: 2,
						},
						cli.StringFlag{
							Name:  "out",
							Usage: "Server certificate output file `NAME`",
						},
					},
					Action: signUser,
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		os.Exit(1)
	}
}

func genKey(c *cli.Context) error {
	size := c.Int("size")
	if size < 1024 {
		return fmt.Errorf("key size must be at least 1024 bits")
	}
	outFileName := c.String("out")
	if outFileName == "" {
		return fmt.Errorf("output file name is required")
	}
	password := c.String("password")

	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %s", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	var keyPemBlock *pem.Block
	if len(password) == 0 {
		keyPemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	} else {
		keyPemBlock, err = x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", keyBytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %s", err)
		}
	}

	var outBuffer bytes.Buffer
	outWriter := bufio.NewWriter(&outBuffer)
	err = pem.Encode(outWriter, keyPemBlock)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %s", err)
	}
	outWriter.Flush()
	err = ioutil.WriteFile(outFileName, outBuffer.Bytes(), 0600)
	if err != nil {
		return fmt.Errorf("failed to save private key: %s", err)
	}

	return nil
}

func genCSR(c *cli.Context) error {
	keyName := c.String("key")
	if keyName == "" {
		return fmt.Errorf("private key file name is required")
	}
	outFileName := c.String("out")
	if outFileName == "" {
		return fmt.Errorf("output file name is required")
	}
	password := c.String("password")
	country := c.String("country")
	province := c.String("province")
	locality := c.String("locality")
	organization := c.String("organization")
	unit := c.String("unit")
	commonName := c.String("cn")
	dnsNames := c.StringSlice("dns")

	var ipAddresses []net.IP
	for _, item := range c.StringSlice("ip") {
		ip := net.ParseIP(item)
		if ip == nil {
			return fmt.Errorf("invalip IP address '%s'", item)
		}
		ipAddresses = append(ipAddresses, ip)
	}

	emails := c.StringSlice("email")

	pemBytes, err := ioutil.ReadFile(keyName)
	if err != nil {
		return fmt.Errorf("failed to load private key: %s", err)
	}

	keyPemBlock, _ := pem.Decode(pemBytes)
	if keyPemBlock == nil {
		return fmt.Errorf("failed to decode private key")
	}

	var keyBytes []byte
	if len(password) == 0 {
		keyBytes = keyPemBlock.Bytes
	} else {
		keyBytes, err = x509.DecryptPEMBlock(keyPemBlock, []byte(password))
		if err != nil {
			return fmt.Errorf("failed to decrypt private key: %s", err)
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %s", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		IPAddresses: ipAddresses,
	}

	if country != "" {
		template.Subject.Country = []string{country}
	}
	if province != "" {
		template.Subject.Province = []string{province}
	}
	if locality != "" {
		template.Subject.Locality = []string{locality}
	}
	if organization != "" {
		template.Subject.Organization = []string{organization}
	}
	if unit != "" {
		template.Subject.OrganizationalUnit = []string{unit}
	}
	if len(dnsNames) != 0 {
		template.DNSNames = dnsNames
	}
	if len(ipAddresses) != 0 {
		template.IPAddresses = ipAddresses
	}
	if len(emails) != 0 {
		template.EmailAddresses = emails
	}

	reqBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate request: %s", err)
	}

	var outBuffer bytes.Buffer
	outWriter := bufio.NewWriter(&outBuffer)
	err = pem.Encode(outWriter, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: reqBytes})
	if err != nil {
		return fmt.Errorf("failed to encode certificate request: %s", err)
	}
	outWriter.Flush()
	err = ioutil.WriteFile(outFileName, outBuffer.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("failed to save certificate request: %s", err)
	}

	return nil
}

func genCA(c *cli.Context) error {
	keyName := c.String("key")
	if keyName == "" {
		return fmt.Errorf("private key name is required")
	}
	organization := c.String("organization")
	if organization == "" {
		return fmt.Errorf("organization name is required")
	}
	validity := c.Int("validity")
	if validity < 1 {
		return fmt.Errorf("validity must be a positive number")
	}
	outFileName := c.String("out")
	if outFileName == "" {
		return fmt.Errorf("output file name is required")
	}
	password := c.String("password")
	country := c.String("country")

	pemBytes, err := ioutil.ReadFile(keyName)
	if err != nil {
		return fmt.Errorf("failed to load private key: %s", err)
	}

	keyPemBlock, _ := pem.Decode(pemBytes)
	if keyPemBlock == nil {
		return fmt.Errorf("failed to decode private key")
	}

	var keyBytes []byte
	if len(password) == 0 {
		keyBytes = keyPemBlock.Bytes
	} else {
		keyBytes, err = x509.DecryptPEMBlock(keyPemBlock, []byte(password))
		if err != nil {
			return fmt.Errorf("failed to decrypt private key: %s", err)
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %s", err)
	}

	serialNumber := big.NewInt(1)
	now := time.Now()

	template := x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(validity, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	if country != "" {
		template.Subject.Country = []string{country}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %s", err)
	}

	var outBuffer bytes.Buffer
	outWriter := bufio.NewWriter(&outBuffer)
	err = pem.Encode(outWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return fmt.Errorf("failed to encode certificate: %s", err)
	}
	outWriter.Flush()
	err = ioutil.WriteFile(outFileName, outBuffer.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("failed to save certificate: %s", err)
	}

	return nil
}

func genCRL(c *cli.Context) error {
	caCertName := c.String("ca-cert")
	if caCertName == "" {
		return fmt.Errorf("certificate authority certificate file name is required")
	}
	validity := c.Int("validity")
	if validity < 0 {
		return fmt.Errorf("validity must be a positive number")
	}
	outFileName := c.String("out")
	if outFileName == "" {
		return fmt.Errorf("output file name is required")
	}
	caKeyName := c.String("ca-key")
	if caKeyName == "" {
		caKeyName = strings.TrimSuffix(caCertName, filepath.Ext(caCertName)) + ".key"
	}
	caPassword := c.String("ca-password")
	certNames := c.StringSlice("cert")

	pemBytes, err := ioutil.ReadFile(caCertName)
	if err != nil {
		return fmt.Errorf("failed to load certificate authority certificate: %s", err)
	}

	certPemBlock, _ := pem.Decode(pemBytes)
	if certPemBlock == nil {
		return fmt.Errorf("failed to decode certificate authority certificate")
	}

	certificate, err := x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate authority certificate: %s", err)
	}

	pemBytes, err = ioutil.ReadFile(caKeyName)
	if err != nil {
		return fmt.Errorf("failed to load certificate authority private key: %s", err)
	}

	keyPemBlock, _ := pem.Decode(pemBytes)
	if keyPemBlock == nil {
		return fmt.Errorf("failed to decode certificate authority private key")
	}

	var keyBytes []byte
	if len(caPassword) == 0 {
		keyBytes = keyPemBlock.Bytes
	} else {
		keyBytes, err = x509.DecryptPEMBlock(keyPemBlock, []byte(caPassword))
		if err != nil {
			return fmt.Errorf("failed to decrypt certificate authority private key: %s", err)
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate authority private key: %s", err)
	}

	now := time.Now().UTC()
	var notAfter time.Time
	if validity == 0 {
		notAfter = certificate.NotAfter
	} else {
		notAfter = now.AddDate(0, 0, validity)
		if notAfter.After(certificate.NotAfter) {
			notAfter = certificate.NotAfter
		}
	}

	var revokedCertificates []pkix.RevokedCertificate

	if _, err := os.Stat(outFileName); !os.IsNotExist(err) {
		crlBytes, err := ioutil.ReadFile(outFileName)
		if err != nil {
			return fmt.Errorf("failed to load original crl: %s", err)
		}
		certs, err := x509.ParseCRL(crlBytes)
		if err != nil {
			return fmt.Errorf("failed to parse original crl: %s", err)
		}
		revokedCertificates = certs.TBSCertList.RevokedCertificates
	}

	for _, certName := range certNames {
		pemBytes, err := ioutil.ReadFile(certName)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %s", err)
		}
		certPemBlock, _ := pem.Decode(pemBytes)
		if certPemBlock == nil {
			return fmt.Errorf("failed to decode certificate authority certificate")
		}
		certificate, err := x509.ParseCertificate(certPemBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate authority certificate: %s", err)
		}
		found := false
		for _, revoked := range revokedCertificates {
			if revoked.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
				found = true
				break
			}
		}
		if !found {
			revokedCertificate := pkix.RevokedCertificate{
				RevocationTime: now,
				SerialNumber:   certificate.SerialNumber,
			}
			revokedCertificates = append(revokedCertificates, revokedCertificate)
		}
	}

	crlBytes, err := certificate.CreateCRL(rand.Reader, privateKey, revokedCertificates, now, notAfter)
	if err != nil {
		return fmt.Errorf("failed create certificate revogation list: %s", err)
	}

	var outBuffer bytes.Buffer
	outWriter := bufio.NewWriter(&outBuffer)
	err = pem.Encode(outWriter, &pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	if err != nil {
		return fmt.Errorf("failed to encode certificate revogation list: %s", err)
	}
	outWriter.Flush()
	err = ioutil.WriteFile(outFileName, outBuffer.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("failed to save certificate revogation list: %s", err)
	}

	return nil
}

func genPkcs(c *cli.Context) error {
	certName := c.String("cert")
	if certName == "" {
		return fmt.Errorf("certificate file name is required")
	}
	keyName := c.String("key")
	if keyName == "" {
		return fmt.Errorf("private key name is required")
	}
	password := c.String("password")
	caCertNames := c.StringSlice("ca-cert")
	outName := c.String("out")
	if outName == "" {
		return fmt.Errorf("output file name is required")
	}

	certPemBytes, err := ioutil.ReadFile(certName)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %s", err)
	}

	certPemBlock, _ := pem.Decode(certPemBytes)
	if certPemBlock == nil {
		return fmt.Errorf("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate : %s", err)
	}

	keyPemBytes, err := ioutil.ReadFile(keyName)
	if err != nil {
		return fmt.Errorf("failed to load private key: %s", err)
	}

	keyPemBlock, _ := pem.Decode(keyPemBytes)
	if keyPemBlock == nil {
		return fmt.Errorf("failed to decode private key")
	}

	var keyBytes []byte
	if len(password) == 0 {
		keyBytes = keyPemBlock.Bytes
	} else {
		keyBytes, err = x509.DecryptPEMBlock(keyPemBlock, []byte(password))
		if err != nil {
			return fmt.Errorf("failed to decrypt certificate authority private key: %s", err)
		}
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate authority private key: %s", err)
	}

	var caCerts []*x509.Certificate

	for _, certName := range caCertNames {
		pemBytes, err := ioutil.ReadFile(certName)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %s", err)
		}
		pemBlock, _ := pem.Decode(pemBytes)
		if pemBlock == nil {
			return fmt.Errorf("failed to decode certificate authority certificate")
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate authority certificate: %s", err)
		}
		caCerts = append(caCerts, cert)
	}

	pfxBytes, err := pkcs12.Encode(rand.Reader, key, cert, caCerts, password)
	if err != nil {
		return fmt.Errorf("failed to encode pcks12: %s", err)
	}

	err = ioutil.WriteFile(outName, pfxBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to save pkcs12: %s", err)
	}

	return nil
}

func signRequest(c *cli.Context, configure func(*x509.Certificate) error) error {
	csrName := c.String("csr")
	if csrName == "" {
		return fmt.Errorf("certificate request file name is required")
	}
	caCertName := c.String("ca-cert")
	if caCertName == "" {
		return fmt.Errorf("certificate authority certificate file name is required")
	}
	outName := c.String("out")
	if outName == "" {
		return fmt.Errorf("output file name is required")
	}
	caKeyName := c.String("ca-key")
	if caKeyName == "" {
		caKeyName = strings.TrimSuffix(caCertName, filepath.Ext(caCertName)) + ".key"
	}
	caPassword := c.String("ca-password")
	crls := c.StringSlice("crl")
	ocsps := c.StringSlice("ocsp")

	pemBytes, err := ioutil.ReadFile(csrName)
	if err != nil {
		return fmt.Errorf("failed to load certificate request: %s", err)
	}

	reqPemBlock, _ := pem.Decode(pemBytes)
	if reqPemBlock == nil {
		return fmt.Errorf("failed to decode certificate request")
	}

	request, err := x509.ParseCertificateRequest(reqPemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate request: %s", err)
	}

	if request.Subject.CommonName == "" {
		return fmt.Errorf("common name field is required")
	}

	pemBytes, err = ioutil.ReadFile(caCertName)
	if err != nil {
		return fmt.Errorf("failed to load certificate authority certificate: %s", err)
	}

	certPemBlock, _ := pem.Decode(pemBytes)
	if certPemBlock == nil {
		return fmt.Errorf("failed to decode certificate authority certificate")
	}

	caCert, err := x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate authority certificate: %s", err)
	}

	pemBytes, err = ioutil.ReadFile(caKeyName)
	if err != nil {
		return fmt.Errorf("failed to load certificate authority private key: %s", err)
	}

	keyPemBlock, _ := pem.Decode(pemBytes)
	if keyPemBlock == nil {
		return fmt.Errorf("failed to decode certificate authority private key")
	}

	var keyBytes []byte
	if len(caPassword) == 0 {
		keyBytes = keyPemBlock.Bytes
	} else {
		keyBytes, err = x509.DecryptPEMBlock(keyPemBlock, []byte(caPassword))
		if err != nil {
			return fmt.Errorf("failed to decrypt certificate authority private key: %s", err)
		}
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate authority private key: %s", err)
	}

	crlsName := strings.TrimSuffix(caKeyName, filepath.Ext(caKeyName)) + ".crls.txt"
	if file, err := os.Open(crlsName); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			crls = append(crls, scanner.Text())
		}
		file.Close()
	}

	ocspsName := strings.TrimSuffix(caKeyName, filepath.Ext(caKeyName)) + ".ocsps.txt"
	if file, err := os.Open(ocspsName); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ocsps = append(ocsps, scanner.Text())
		}
	}

	serialNumber := big.NewInt(time.Now().UnixNano())
	now := time.Now()

	if now.After(caCert.NotAfter) {
		return fmt.Errorf("CA certificate (%s) is expired", caCert.Subject)
	}

	template := x509.Certificate{
		IsCA:                  false,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName: request.Subject.CommonName,
		},
		NotBefore: now,
		NotAfter:  now,
	}

	if len(request.Subject.Country) != 0 {
		template.Subject.Country = request.Subject.Country
	} else if len(caCert.Subject.Country) != 0 {
		template.Subject.Country = caCert.Subject.Country
	}
	if len(request.Subject.Organization) != 0 {
		template.Subject.Organization = request.Subject.Organization
	} else if len(caCert.Subject.Organization) != 0 {
		template.Subject.Organization = caCert.Subject.Organization
	}
	if len(request.Subject.OrganizationalUnit) != 0 {
		template.Subject.OrganizationalUnit = request.Subject.OrganizationalUnit
	}
	if len(request.DNSNames) != 0 {
		template.DNSNames = request.DNSNames
	}
	if len(request.IPAddresses) != 0 {
		template.IPAddresses = request.IPAddresses
	}
	if len(request.EmailAddresses) != 0 {
		template.EmailAddresses = request.EmailAddresses
	}
	if len(crls) != 0 {
		template.CRLDistributionPoints = crls
	} else if len(caCert.CRLDistributionPoints) != 0 {
		template.CRLDistributionPoints = caCert.CRLDistributionPoints
	}
	if len(ocsps) != 0 {
		template.OCSPServer = ocsps
	} else if len(caCert.OCSPServer) != 0 {
		template.OCSPServer = caCert.OCSPServer
	}

	if err := configure(&template); err != nil {
		return fmt.Errorf("failed to configure certificate policies: %s", err)
	}

	if template.NotAfter.After(caCert.NotAfter) {
		return fmt.Errorf("CA certificate will be expired before certificate expiration")
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, request.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %s", err)
	}

	var outBuffer bytes.Buffer
	outWriter := bufio.NewWriter(&outBuffer)
	err = pem.Encode(outWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return fmt.Errorf("failed to encode certificate: %s", err)
	}
	outWriter.Flush()
	err = ioutil.WriteFile(outName, outBuffer.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("failed to save certificate: %s", err)
	}

	return nil
}

func signCA(c *cli.Context) error {
	maxPathLen := c.Int("max-path-len")
	if maxPathLen < 0 {
		return fmt.Errorf("path length must be equal or greater than 0")
	}
	validity := c.Int("validity")
	if validity < 1 {
		return fmt.Errorf("validity must be a positive number")
	}

	configure := func(template *x509.Certificate) error {
		template.IsCA = true
		template.MaxPathLen = maxPathLen
		template.MaxPathLenZero = maxPathLen == 0
		template.BasicConstraintsValid = true
		template.NotAfter = template.NotBefore.AddDate(validity, 0, 0)
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.DNSNames = nil
		template.IPAddresses = nil
		template.EmailAddresses = nil
		return nil
	}

	return signRequest(c, configure)
}

func signCode(c *cli.Context) error {
	validity := c.Int("validity")
	if validity < 1 {
		return fmt.Errorf("validity must be a positive number")
	}

	configure := func(template *x509.Certificate) error {
		template.NotAfter = template.NotBefore.AddDate(validity, 0, 0)
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		template.DNSNames = nil
		template.IPAddresses = nil
		template.EmailAddresses = nil
		return nil
	}

	return signRequest(c, configure)
}

func signServer(c *cli.Context) error {
	validity := c.Int("validity")
	if validity < 1 {
		return fmt.Errorf("validity must be a positive number")
	}

	configure := func(template *x509.Certificate) error {
		template.NotAfter = template.NotBefore.AddDate(validity, 0, 0)
		template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.EmailAddresses = nil
		if len(template.DNSNames) == 0 {
			template.DNSNames = []string{template.Subject.CommonName}
		}
		return nil
	}

	return signRequest(c, configure)
}

func signUser(c *cli.Context) error {
	validity := c.Int("validity")
	if validity < 1 {
		return fmt.Errorf("validity must be a positive number")
	}

	configure := func(template *x509.Certificate) error {
		template.NotAfter = template.NotBefore.AddDate(validity, 0, 0)
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
		template.DNSNames = nil
		template.IPAddresses = nil
		return nil
	}

	return signRequest(c, configure)
}
