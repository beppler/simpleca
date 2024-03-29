package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/exp/slices"
	"software.sslmate.com/src/go-pkcs12"
)

var version = ""

func main() {
	app := cli.NewApp()
	app.Name = "simpleca"
	app.Usage = "Simple Certificate Authority"
	app.EnableBashCompletion = true
	app.Version = version
	app.Commands = []*cli.Command{
		{
			Name:  "crl",
			Usage: "Create/Update a certificate revogation list (CRL)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "ca-cert",
					Usage:    "Certificate authority certificate file `NAME`",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "ca-key",
					Usage: "Certificare authority private key file `NAME`",
				},
				&cli.StringFlag{
					Name:  "ca-password",
					Usage: "private key password",
				},
				&cli.IntFlag{
					Name:  "validity",
					Usage: "Validity time in `days` (0 to copy certificate authority validity)",
					Value: 7,
					Action: func(ctx *cli.Context, validity int) error {
						if validity < 1 {
							return fmt.Errorf("validity must be a positive number")
						}
						return nil
					},
				},
				&cli.StringSliceFlag{
					Name:  "cert",
					Usage: "Certificate to be included on CRL",
				},
				&cli.StringFlag{
					Name:  "in",
					Usage: "Certificate revogation list input file `NAME`",
				},
				&cli.StringFlag{
					Name:  "out",
					Usage: "Certificate revogation list output file `NAME`",
				},
			},
			Action: createCRL,
		},
		{
			Name:  "csr",
			Usage: "Create a certificate request",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "key",
					Usage:    "Private key file `NAME`",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "password",
					Usage: "private key password",
				},
				&cli.StringFlag{
					Name:  "country",
					Usage: "Country code (ex. US) for certificate request",
				},
				&cli.StringFlag{
					Name:  "province",
					Usage: "Province (ex. California) for certificate request",
				},
				&cli.StringFlag{
					Name:  "locality",
					Usage: "Locality (ex. Los Angeles) for certificate request",
				},
				&cli.StringFlag{
					Name:  "organization",
					Usage: "Organization for certificate request",
				},
				&cli.StringFlag{
					Name:  "unit",
					Usage: "Organizational unit for certificate request",
				},
				&cli.StringFlag{
					Name:  "cn",
					Usage: "Common name for certificate request",
				},
				&cli.StringSliceFlag{
					Name:  "dns",
					Usage: "Alternative host name for certificate request",
				},
				&cli.StringSliceFlag{
					Name:  "ip",
					Usage: "Alternative IP address for certificate request",
				},
				&cli.StringSliceFlag{
					Name:  "email",
					Usage: "Alternative RFC822 email address for certificate request",
				},
				&cli.StringFlag{
					Name:  "out",
					Usage: "Certificate request output file `NAME`",
				},
			},
			Action: createCSR,
		},
		{
			Name:  "key",
			Usage: "Private key support",
			Subcommands: []*cli.Command{
				{
					Name:  "create",
					Usage: "Create private keys",
					Subcommands: []*cli.Command{
						{
							Name:  "ecdsa",
							Usage: "Create ECDSA private key",
							Flags: []cli.Flag{
								&cli.StringFlag{
									Name:        "type",
									Usage:       "Private key curve type `TYPE` (p256, p384, p521)",
									Value:       "p384",
									DefaultText: "p384",
									Action: func(ctx *cli.Context, v string) error {
										types := []string{"p256", "p384", "p521"}
										if !slices.Contains(types, v) {
											return fmt.Errorf("invalid curve type %v, valid types are %v", v, strings.Join(types, ", "))
										}
										return nil
									},
								},
								&cli.StringFlag{
									Name:  "password",
									Usage: "Private key `PASSWORD`",
								},
								&cli.StringFlag{
									Name:  "out",
									Usage: "Private key output file `NAME`",
								},
							},
							Action: createECDSAKey,
						},
						{
							Name:  "rsa",
							Usage: "Create RSA private key",
							Flags: []cli.Flag{
								&cli.IntFlag{
									Name:  "size",
									Usage: "Private key `SIZE` (in bits for RSA)",
									Value: 2048,
									Action: func(ctx *cli.Context, v int) error {
										quotient, remainder := bits.Div32(0, uint32(v), 1024)
										if quotient < 1 || remainder != 0 {
											return fmt.Errorf("key size must be at least 1024 bits and a multiple of 1024")
										}
										return nil
									},
								},
								&cli.StringFlag{
									Name:  "password",
									Usage: "Private key `PASSWORD`",
								},
								&cli.StringFlag{
									Name:  "out",
									Usage: "Private key output file `NAME`",
								},
							},
							Action: createRSAKey,
						},
					},
				},
			},
		},
		{
			Name:  "pkcs",
			Usage: "PCKS12 support",
			Subcommands: []*cli.Command{
				{
					Name:  "encode",
					Usage: "Encode a PKCS12 file from certificate and private key",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "cert",
							Usage:    "Certificate file `NAME`",
							Required: true,
						},
						&cli.StringFlag{
							Name:     "key",
							Usage:    "Private key file `NAME`",
							Required: true,
						},
						&cli.StringFlag{
							Name:  "password",
							Usage: "Private key `PASSWORD`",
						},
						&cli.StringSliceFlag{
							Name:  "ca-cert",
							Usage: "Certificate authorities certificate file `NAME`",
						},
						&cli.StringFlag{
							Name:  "out",
							Usage: "PKCS12 output file `NAME`",
						},
					},
					Action: encodePkcs,
				},
			},
		},
		{
			Name:  "sign",
			Usage: "Sign a certificate request",
			Subcommands: []*cli.Command{
				{
					Name:  "ca",
					Usage: "Sign a certificate authority request",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "csr",
							Usage:    "Certificate request file `NAME`",
							Required: true,
						},
						&cli.StringFlag{
							Name:  "ca-cert",
							Usage: "Certificate authority certificate file `NAME`",
						},
						&cli.StringFlag{
							Name:  "ca-key",
							Usage: "Certificare authority private key file `NAME`",
						},
						&cli.StringFlag{
							Name:  "ca-password",
							Usage: "private key `PASSWORD`",
						},
						&cli.StringSliceFlag{
							Name:  "crl",
							Usage: "CRL distribution points `URI` for certificate",
						},
						&cli.IntFlag{
							Name:  "max-path-len",
							Usage: "Maximum number of subordinate CAs",
							Value: 0,
							Action: func(ctx *cli.Context, maxPathLen int) error {
								if maxPathLen < 0 {
									return fmt.Errorf("path length must be equal or greater than 0")
								}
								return nil
							},
						},
						&cli.IntFlag{
							Name:  "validity",
							Usage: "Validity time in `YEARS`",
							Value: 5,
							Action: func(ctx *cli.Context, validity int) error {
								if validity < 1 {
									return fmt.Errorf("validity must be a positive number")
								}
								return nil
							},
						},
						&cli.StringFlag{
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
						&cli.StringFlag{
							Name:     "csr",
							Usage:    "Certificate request file `NAME`",
							Required: true,
						},
						&cli.StringFlag{
							Name:  "ca-cert",
							Usage: "Certificate authority certificate file `NAME`",
						},
						&cli.StringFlag{
							Name:  "ca-key",
							Usage: "Certificare authority private key file `NAME`",
						},
						&cli.StringFlag{
							Name:  "ca-password",
							Usage: "private key `PASSWORD`",
						},
						&cli.StringSliceFlag{
							Name:  "crl",
							Usage: "CRL distribution points `URI` for certificate",
						},
						&cli.StringSliceFlag{
							Name:  "ocsp",
							Usage: "OCSP servers `URI` for certificate",
						},
						&cli.IntFlag{
							Name:  "validity",
							Usage: "Validity time in `YEARS`",
							Value: 2,
							Action: func(ctx *cli.Context, validity int) error {
								if validity < 1 {
									return fmt.Errorf("validity must be a positive number")
								}
								return nil
							},
						},
						&cli.StringFlag{
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
						&cli.StringFlag{
							Name:     "csr",
							Usage:    "Certificate request file `NAME`",
							Required: true,
						},
						&cli.StringFlag{
							Name:  "ca-cert",
							Usage: "Certificate authority certificate file `NAME`",
						},
						&cli.StringFlag{
							Name:  "ca-key",
							Usage: "Certificare authority private key file `NAME`",
						},
						&cli.StringFlag{
							Name:  "ca-password",
							Usage: "private key `PASSWORD`",
						},
						&cli.StringSliceFlag{
							Name:  "crl",
							Usage: "CRL distribution points `URI` for certificate",
						},
						&cli.StringSliceFlag{
							Name:  "ocsp",
							Usage: "OCSP servers `URI` for certificate",
						},
						&cli.IntFlag{
							Name:  "validity",
							Usage: "Validity time in `YEARS`",
							Value: 2,
							Action: func(ctx *cli.Context, validity int) error {
								if validity < 1 {
									return fmt.Errorf("validity must be a positive number")
								}
								return nil
							},
						},
						&cli.StringFlag{
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
						&cli.StringFlag{
							Name:     "csr",
							Usage:    "Certificate request file `NAME`",
							Required: true,
						},
						&cli.StringFlag{
							Name:  "ca-cert",
							Usage: "Certificate authority certificate file `NAME`",
						},
						&cli.StringFlag{
							Name:  "ca-key",
							Usage: "Certificare authority private key file `NAME`",
						},
						&cli.StringFlag{
							Name:  "ca-password",
							Usage: "private key `PASSWORD`",
						},
						&cli.StringSliceFlag{
							Name:  "crl",
							Usage: "CRL distribution points `URI` for certificate",
						},
						&cli.StringSliceFlag{
							Name:  "ocsp",
							Usage: "OCSP servers `URI` for certificate",
						},
						&cli.IntFlag{
							Name:  "validity",
							Usage: "Validity time in `YEARS`",
							Value: 2,
							Action: func(ctx *cli.Context, validity int) error {
								if validity < 1 {
									return fmt.Errorf("validity must be a positive number")
								}
								return nil
							},
						},
						&cli.StringFlag{
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

func createECDSAKey(c *cli.Context) error {
	curveType := c.String("type")
	password := c.String("password")
	outFileName := c.String("out")

	curve := map[string]elliptic.Curve{
		"p256": elliptic.P256(),
		"p384": elliptic.P384(),
		"p521": elliptic.P521(),
	}[curveType]

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	keyPemBlock, err := marshalPrivateKey(privateKey, password)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPemBytes, err := encodePemBlock(keyPemBlock)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	if err := writeBytes(keyPemBytes, outFileName); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	return nil
}

func createRSAKey(c *cli.Context) error {
	size := c.Int("size")
	password := c.String("password")
	outFileName := c.String("out")

	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	keyPemBlock, err := marshalPrivateKey(privateKey, password)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPemBytes, err := encodePemBlock(keyPemBlock)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	if err := writeBytes(keyPemBytes, outFileName); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	return nil
}

func createCSR(c *cli.Context) error {
	keyName := c.String("key")
	password := c.String("password")
	country := c.String("country")
	province := c.String("province")
	locality := c.String("locality")
	organization := c.String("organization")
	unit := c.String("unit")
	commonName := c.String("cn")
	dnsNames := c.StringSlice("dns")
	outFileName := c.String("out")

	var ipAddresses []net.IP
	for _, item := range c.StringSlice("ip") {
		ip := net.ParseIP(item)
		if ip == nil {
			return fmt.Errorf("invalip IP address '%s'", item)
		}
		ipAddresses = append(ipAddresses, ip)
	}

	emails := c.StringSlice("email")

	pemBytes, err := os.ReadFile(keyName)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	keyPemBlock, _ := pem.Decode(pemBytes)
	if keyPemBlock == nil {
		return fmt.Errorf("failed to decode private key")
	}

	privateKey, err := parsePrivateKey(keyPemBlock, password)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
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
		return fmt.Errorf("failed to create certificate request: %w", err)
	}

	reqPemBytes, err := encodePemBlock(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: reqBytes})
	if err != nil {
		return fmt.Errorf("failed to encode certificate request: %w", err)
	}

	if err = writeBytes(reqPemBytes, outFileName); err != nil {
		return fmt.Errorf("failed to save certificate request: %w", err)
	}

	return nil
}

func createCRL(c *cli.Context) error {
	caCertName := c.String("ca-cert")
	validity := c.Int("validity")
	caKeyName := c.String("ca-key")
	if caKeyName == "" {
		caKeyName = strings.TrimSuffix(caCertName, filepath.Ext(caCertName)) + ".key"
	}
	caPassword := c.String("ca-password")
	certNames := c.StringSlice("cert")
	inFileName := c.String("in")
	outFileName := c.String("out")

	pemBytes, err := os.ReadFile(caCertName)
	if err != nil {
		return fmt.Errorf("failed to load certificate authority certificate: %w", err)
	}

	certPemBlock, _ := pem.Decode(pemBytes)
	if certPemBlock == nil {
		return fmt.Errorf("failed to decode certificate authority certificate")
	}

	certificate, err := x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate authority certificate: %w", err)
	}

	pemBytes, err = os.ReadFile(caKeyName)
	if err != nil {
		return fmt.Errorf("failed to load certificate authority private key: %w", err)
	}

	keyPemBlock, _ := pem.Decode(pemBytes)
	if keyPemBlock == nil {
		return fmt.Errorf("failed to decode certificate authority private key")
	}

	privateKey, err := parsePrivateKey(keyPemBlock, caPassword)
	if err != nil {
		return fmt.Errorf("failed to parse certificate authority private key: %w", err)
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

	if inFileName != "" {
		crlBytes, err := os.ReadFile(inFileName)
		if err != nil {
			return fmt.Errorf("failed to load original crl: %w", err)
		}
		certs, err := x509.ParseCRL(crlBytes)
		if err != nil {
			return fmt.Errorf("failed to parse original crl: %w", err)
		}
		revokedCertificates = certs.TBSCertList.RevokedCertificates
	}

	for _, certName := range certNames {
		pemBytes, err := os.ReadFile(certName)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}
		certPemBlock, _ := pem.Decode(pemBytes)
		if certPemBlock == nil {
			return fmt.Errorf("failed to decode certificate authority certificate")
		}
		certificate, err := x509.ParseCertificate(certPemBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate authority certificate: %w", err)
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
		return fmt.Errorf("failed create certificate revogation list: %w", err)
	}

	crlPemBytes, err := encodePemBlock(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	if err != nil {
		return fmt.Errorf("failed to encode certificate revogation list: %w", err)
	}

	if err := writeBytes(crlPemBytes, outFileName); err != nil {
		return fmt.Errorf("failed to save certificate revogation list: %w", err)
	}

	return nil
}

func encodePkcs(c *cli.Context) error {
	certName := c.String("cert")
	keyName := c.String("key")
	password := c.String("password")
	caCertNames := c.StringSlice("ca-cert")
	outFileName := c.String("out")

	certPemBytes, err := os.ReadFile(certName)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	certPemBlock, _ := pem.Decode(certPemBytes)
	if certPemBlock == nil {
		return fmt.Errorf("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate : %w", err)
	}

	keyPemBytes, err := os.ReadFile(keyName)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	keyPemBlock, _ := pem.Decode(keyPemBytes)
	if keyPemBlock == nil {
		return fmt.Errorf("failed to decode private key")
	}

	key, err := parsePrivateKey(keyPemBlock, password)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	var caCerts []*x509.Certificate

	for _, certName := range caCertNames {
		pemBytes, err := os.ReadFile(certName)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}
		pemBlock, _ := pem.Decode(pemBytes)
		if pemBlock == nil {
			return fmt.Errorf("failed to decode certificate authority certificate")
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate authority certificate: %w", err)
		}
		caCerts = append(caCerts, cert)
	}

	pfxBytes, err := pkcs12.Encode(rand.Reader, key, cert, caCerts, password)
	if err != nil {
		return fmt.Errorf("failed to encode pcks12: %w", err)
	}

	if err := writeBytes(pfxBytes, outFileName); err != nil {
		return fmt.Errorf("failed to save pkcs12: %w", err)
	}

	return nil
}

func signCA(c *cli.Context) error {
	maxPathLen := c.Int("max-path-len")

	configure := func(template *x509.Certificate) error {
		template.IsCA = true
		template.SerialNumber = big.NewInt(1)
		template.MaxPathLen = maxPathLen
		template.MaxPathLenZero = c.IsSet("max-path-len")
		template.BasicConstraintsValid = true
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.DNSNames = nil
		template.IPAddresses = nil
		template.EmailAddresses = nil
		return nil
	}

	return signRequest(c, true, configure)
}

func signCode(c *cli.Context) error {
	configure := func(template *x509.Certificate) error {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		template.DNSNames = nil
		template.IPAddresses = nil
		template.EmailAddresses = nil
		return nil
	}

	return signRequest(c, false, configure)
}

func signServer(c *cli.Context) error {
	configure := func(template *x509.Certificate) error {
		template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.EmailAddresses = nil
		if len(template.DNSNames) == 0 {
			template.DNSNames = []string{template.Subject.CommonName}
		}
		return nil
	}

	return signRequest(c, false, configure)
}

func signUser(c *cli.Context) error {
	configure := func(template *x509.Certificate) error {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
		template.DNSNames = nil
		template.IPAddresses = nil
		return nil
	}

	return signRequest(c, false, configure)
}

func signRequest(c *cli.Context, allowSelfSign bool, configure func(*x509.Certificate) error) error {
	csrName := c.String("csr")
	caCertName := c.String("ca-cert")
	if !allowSelfSign && caCertName == "" {
		return fmt.Errorf("certificate authority certificate file name is required")
	}
	caKeyName := c.String("ca-key")
	if caKeyName == "" {
		if caCertName != "" {
			caKeyName = strings.TrimSuffix(caCertName, filepath.Ext(caCertName)) + ".key"
		} else if csrName != "" {
			caKeyName = strings.TrimSuffix(csrName, filepath.Ext(csrName)) + ".key"
		} else {
			return fmt.Errorf("certificate authority private key file name is required")
		}
	}
	caPassword := c.String("ca-password")
	validity := c.Int("validity")
	crls := c.StringSlice("crl")
	outFileName := c.String("out")

	pemBytes, err := os.ReadFile(csrName)
	if err != nil {
		return fmt.Errorf("failed to load certificate request: %w", err)
	}

	reqPemBlock, _ := pem.Decode(pemBytes)
	if reqPemBlock == nil {
		return fmt.Errorf("failed to decode certificate request")
	}

	request, err := x509.ParseCertificateRequest(reqPemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate request: %w", err)
	}

	if request.Subject.CommonName == "" {
		return fmt.Errorf("common name field is required")
	}

	pemBytes, err = os.ReadFile(caKeyName)
	if err != nil {
		return fmt.Errorf("failed to load certificate authority private key: %w", err)
	}

	keyPemBlock, _ := pem.Decode(pemBytes)
	if keyPemBlock == nil {
		return fmt.Errorf("failed to decode certificate authority private key")
	}

	caKey, err := parsePrivateKey(keyPemBlock, caPassword)
	if err != nil {
		return fmt.Errorf("failed to parse certificate authority private key: %w", err)
	}

	serialNumber := big.NewInt(time.Now().UnixNano())
	now := time.Now()

	template := x509.Certificate{
		IsCA:                  false,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName:         request.Subject.CommonName,
			Country:            request.Subject.Country,
			Organization:       request.Subject.Organization,
			OrganizationalUnit: request.Subject.OrganizationalUnit,
		},
		DNSNames:              request.DNSNames,
		IPAddresses:           request.IPAddresses,
		EmailAddresses:        request.EmailAddresses,
		CRLDistributionPoints: crls,
		NotBefore:             now,
		NotAfter:              now.AddDate(validity, 0, 0),
	}

	var caCert *x509.Certificate
	if caCertName == "" {
		caCert = &template
	} else {
		pemBytes, err = os.ReadFile(caCertName)
		if err != nil {
			return fmt.Errorf("failed to load certificate authority certificate: %w", err)
		}

		certPemBlock, _ := pem.Decode(pemBytes)
		if certPemBlock == nil {
			return fmt.Errorf("failed to decode certificate authority certificate")
		}

		caCert, err = x509.ParseCertificate(certPemBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate authority certificate: %w", err)
		}

		if now.After(caCert.NotAfter) {
			return fmt.Errorf("CA certificate (%s) is expired", caCert.Subject)
		}

		if template.NotAfter.After(caCert.NotAfter) {
			template.NotAfter = caCert.NotAfter
		}

		if len(template.Subject.Country) == 0 && len(caCert.Subject.Country) != 0 {
			template.Subject.Country = caCert.Subject.Country
		}
		if len(template.Subject.Organization) == 0 && len(caCert.Subject.Organization) != 0 {
			template.Subject.Organization = caCert.Subject.Organization
		}
		if len(template.CRLDistributionPoints) == 0 && len(caCert.CRLDistributionPoints) != 0 {
			template.CRLDistributionPoints = append(template.CRLDistributionPoints, caCert.CRLDistributionPoints...)
		}
		if len(template.OCSPServer) == 0 && len(caCert.OCSPServer) != 0 {
			template.OCSPServer = append(template.OCSPServer, caCert.OCSPServer...)
		}

		crlsName := strings.TrimSuffix(caKeyName, filepath.Ext(caKeyName)) + ".crls.txt"
		if file, err := os.Open(crlsName); err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				template.CRLDistributionPoints = append(template.CRLDistributionPoints, scanner.Text())
			}
			file.Close()
		}
	}

	if err := configure(&template); err != nil {
		return fmt.Errorf("failed to configure certificate policies: %w", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, request.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certPemBytes, err := encodePemBlock(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	if err := writeBytes(certPemBytes, outFileName); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	return nil
}

func encodePemBlock(block *pem.Block) ([]byte, error) {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func marshalPrivateKey(privateKey crypto.PrivateKey, password string) (*pem.Block, error) {
	var keyBytes []byte
	var keyType string
	var err error
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
		keyType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal ECDSA private key: %w", err)
		}
		keyType = "EC PRIVATE KEY"
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}

	if password == "" {
		return &pem.Block{Type: keyType, Bytes: keyBytes}, nil
	} else {
		keyPemBlock, err := pemutil.EncryptPKCS8PrivateKey(rand.Reader, keyBytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %s", err)
		}
		return keyPemBlock, nil
	}
}

func parsePrivateKey(keyPemBlock *pem.Block, password string) (crypto.PrivateKey, error) {
	var keyBytes []byte
	var err error
	if password == "" {
		keyBytes = keyPemBlock.Bytes
	} else {
		keyBytes, err = pemutil.DecryptPEMBlock(keyPemBlock, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt certificate authority private key: %w", err)
		}
	}

	switch keyPemBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", keyPemBlock.Type)
	}
}

func writeBytes(data []byte, outFileName string) (err error) {
	if outFileName == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(outFileName, data, 0600)
	}
	return err
}
