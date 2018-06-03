package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/tjamet/local-https-dev/server/acme"
	"github.com/tjamet/local-https-dev/server/cache"
	"github.com/urfave/cli"
)

func getPostDomains(c *gin.Context) []string {
	b, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return nil
	}
	return strings.Fields(string(b))
}

func getCertificate(c *cli.Context, client *acme.Client, domains ...string) (*acme.Certificate, error) {
	wCard := []string{}
	if c.String("domain") != "" && domains != nil {
		for _, domain := range domains[:] {
			w := "*" + domain[strings.Index(domain, "."):]
			existing := false
			for _, d := range wCard[:] {
				if d == w {
					existing = true
				}
			}
			if !existing {
				wCard = append(wCard, w)
			}
		}
		if len(wCard) > c.Int("maxDomains") {
			return nil, fmt.Errorf("request exceeded the maximum number of accepted domains")
		}
		for _, domain := range wCard {
			if !strings.HasSuffix(domain, c.String("domain")) {
				return nil, fmt.Errorf("all requested domains should end with %s", c.String("domain"))
			}
		}
	}
	return client.GetCertificate(wCard...)
}

func replyHaproxyCertificates(c *gin.Context, certificate *acme.Certificate, err error) {
	if !c.IsAborted() {
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		b := bytes.NewBuffer(nil)
		b.Write(certificate.IssuerCertificate)
		b.Write(certificate.Certificate)
		b.Write(certificate.PrivateKey)
		c.Header("Content-Length", strconv.Itoa(b.Len()))
		c.Status(http.StatusOK)
		c.Writer.Write(b.Bytes())
	}
}

func replyJSONCertificates(c *gin.Context, certificate *acme.Certificate, err error) {
	if !c.IsAborted() {
		if err != nil {
			c.JSON(http.StatusInternalServerError, struct {
				Message string `json:"message"`
			}{
				Message: err.Error(),
			})
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		c.JSON(http.StatusOK, certificate)
	}
}

func loadSecret(path string) (interface{}, error) {
	var key []byte
	if strings.HasPrefix(path, "http") {
		r, err := http.Get(path)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to retrieve key path %s", path))
		}
		defer r.Body.Close()
		if r.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to retrieve key path %s. Unexpected code %d", path, r.StatusCode)
		}
		key, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to retrieve key path %s", path))
		}
	} else {
		keyPath, err := homedir.Expand(path)
		if err != nil {
			return nil, errors.Wrap(err, "failed to retrieve key path")
		}
		key, err = ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("Failed to read key path %s", path))
		}
	}
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		fmt.Printf("Failed to parse PEM for path %s, using raw data as key\n", path)
		return key, nil
	}
	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to parse key certificate")
		}
		return cert.PublicKey, nil
	}
	if strings.HasSuffix(block.Type, "PUBLIC KEY") {
		return x509.ParsePKIXPublicKey(block.Bytes)
	}
	return nil, fmt.Errorf("Unsupported pem format %s, expecting CERTIFICATE or PUBLIC KEY suffix", block.Type)
}

func run(c *cli.Context) error {
	path, err := homedir.Expand(c.String("path"))
	if err != nil {
		return errors.Wrap(err, "failed to retrieve cache path")
	}
	client, err := acme.New(
		log.New(os.Stderr, "legolog: ", log.LstdFlags),
		c.String("email"),
		c.String("dns"),
		c.String("server"),
		cache.NewFileSystemCache(path),
	)
	if err != nil {
		return errors.Wrap(err, "failed to create acme client")
	}

	r := gin.Default()
	if !c.Bool("disable-authentication") {
		publicKey, err := loadSecret(c.String("key"))
		if err != nil {
			return errors.Wrap(err, "failed to load public key")
		}
		r.Use(func(c *gin.Context) {
			auth := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
			if len(auth) != 2 || auth[0] != "Basic" {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			payload, err := base64.StdEncoding.DecodeString(auth[1])
			if err != nil {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			pair := strings.SplitN(string(payload), ":", 2)
			if len(auth) != 2 {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			tokenClaims := jwt.StandardClaims{}
			_, err = jwt.ParseWithClaims(pair[1], &tokenClaims, func(token *jwt.Token) (interface{}, error) {
				return publicKey, nil
			})
			if err != nil {
				fmt.Println(err)
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			err = tokenClaims.Valid()
			if err != nil {
				fmt.Println(err)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
		})
	}
	r.POST("/haproxy", func(gc *gin.Context) {
		crt, err := getCertificate(c, client, getPostDomains(gc)...)
		replyHaproxyCertificates(gc, crt, err)
	})
	r.POST("/json", func(gc *gin.Context) {
		crt, err := getCertificate(c, client, getPostDomains(gc)...)
		replyJSONCertificates(gc, crt, err)
	})
	r.GET("/haproxy/:domain", func(gc *gin.Context) {
		crt, err := getCertificate(c, client, gc.Param("domain"))
		replyHaproxyCertificates(gc, crt, err)
	})
	r.GET("/json/:domain", func(gc *gin.Context) {
		crt, err := getCertificate(c, client, gc.Param("domain"))
		replyJSONCertificates(gc, crt, err)
	})
	return http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", c.Uint("port")), r)
}

// this is not recommended but prevents from re-writing lego
func dockerSecretsToEnv() {
	// generater helper cat README.md  | grep td | sed 's:([^)]*)::g' | sed -e 's:.*<td>::g' -e 's:</td>::g' -e 's/<br>/\'$'\n/g' | grep -v ' \t' | grep -v -E '[a-z]' | sed 's:\(.*\):"\1",:g' | grep -v '""'
	for _, key := range []string{
		"AURORA_USER_ID",
		"AURORA_KEY",
		"AURORA_ENDPOINT",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_SUBSCRIPTION_ID",
		"AZURE_TENANT_ID",
		"CLOUDFLARE_EMAIL",
		"CLOUDFLARE_API_KEY",
		"CLOUDXNS_API_KEY",
		"CLOUDXNS_SECRET_KEY",
		"DO_AUTH_TOKEN",
		"DNSIMPLE_EMAIL",
		"DNSIMPLE_OAUTH_TOKEN",
		"DNSMADEEASY_API_KEY",
		"DNSMADEEASY_API_SECRET",
		"DNSMADEEASY_SANDBOX ",
		"DNSPOD_API_KEY",
		"DYN_CUSTOMER_NAME",
		"DYN_USER_NAME",
		"DYN_PASSWORD",
		"GANDI_API_KEY",
		"GANDIV5_API_KEY",
		"GODADDY_API_KEY",
		"GODADDY_API_SECRET",
		"GCE_PROJECT",
		"GCE_DOMAIN",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"DNS_ZONE",
		"LINODE_API_KEY",
		"NAMECHEAP_API_USER",
		"NAMECHEAP_API_KEY",
		"NS1_API_KEY",
		"NAMECOM_USERNAME",
		"NAMECOM_API_TOKEN",
		"OVH",
		"OVH_ENDPOINT",
		"OVH_APPLICATION_KEY",
		"OVH_APPLICATION_SECRET",
		"OVH_CONSUMER_KEY",
		"OTC_DOMAIN_NAME",
		"OTC_USER_NAME",
		"OTC_PASSWORD",
		"OTC_PROJECT_NAME",
		"OTC_IDENTITY_ENDPOINT ",
		"PDNS_API_URL",
		"PDNS_API_KEY",
		"RACKSPACE_USER",
		"RACKSPACE_API_KEY",
		"RFC2136_NAMESERVER",
		"RFC2136_TSIG_ALGORITHM",
		"RFC2136_TSIG_KEY",
		"RFC2136_TSIG_SECRET",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"VULTR_API_KEY",
	}[:] {
		file, err := os.Open("/run/secrets/" + key)
		if err == nil {
			defer file.Close()
			content, err := ioutil.ReadAll(file)
			if err == nil {
				log.Printf("Populating env variable %s from docker secrets", key)
				os.Setenv(key, strings.Trim(string(content), " \t\n"))
			}
		}
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "local-https-dev-server"
	app.Usage = "A simple HTTP server to serve certificates"

	app.Version = "0.0.0"

	app.Before = func(c *cli.Context) error {

		dockerSecretsToEnv()
		if !c.Bool("accept-tos") {
			return fmt.Errorf("You need to accept Let's Encrypt Terms Of Service to run this tool")
		}
		if c.String("email") == "" {
			return fmt.Errorf("You need to provide your email")
		}
		if c.String("dns") == "" {
			return fmt.Errorf("You need to provide the dns provider for the DNS challenge")
		}
		return nil
	}

	app.Action = run
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "domain, d",
			Usage: "Specify the allowed domain suffix",
		},
		cli.StringFlag{
			Name:  "server, s",
			Value: "https://acme-v02.api.letsencrypt.org/directory",
			Usage: "CA hostname (and optionally :port). The server certificate must be trusted in order to avoid further modifications to the client.",
		},
		cli.StringFlag{
			Name:  "email, m",
			Usage: "Email used for registration and recovery contact.",
		},
		cli.StringFlag{
			Name:  "dns",
			Usage: "Solve a DNS challenge using the specified provider.",
		},
		cli.StringFlag{
			Name:  "path",
			Value: "~/.dev-acme",
			Usage: "Directory where to store cache (let's encrypt account and certificates).",
		},
		cli.StringFlag{
			Name:  "key",
			Usage: "The path to the JWT signing key.",
		},
		cli.BoolFlag{
			Name:  "disable-authentication",
			Usage: "Disables authentication",
		},
		cli.BoolFlag{
			Name:  "accept-tos, a",
			Usage: "By setting this flag to true you indicate that you accept the current Let's Encrypt terms of service.",
		},
		cli.UintFlag{
			Name:  "port, p",
			Value: 8080,
			Usage: "The port the server should listen to.",
		},
		cli.UintFlag{
			Name:  "maxDomains, n",
			Value: 1,
			Usage: "The maximum number of domains to include in the certificate.",
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
