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
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		c.JSON(http.StatusOK, certificate)
	}
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
		keyPath, err := homedir.Expand(c.String("key"))
		if err != nil {
			return errors.Wrap(err, "failed to retrieve key path")
		}
		key, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode([]byte(key))
		var publicKey interface{}
		if block == nil {
			fmt.Printf("Failed to parse PEM for path %s, using raw data as key\n", keyPath)
			publicKey = key
		} else {
			publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return err
			}
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

func main() {
	app := cli.NewApp()
	app.Name = "local-https-dev-server"
	app.Usage = "A simple HTTP server to serve certificates"

	app.Version = "0.0.0"

	app.Before = func(c *cli.Context) error {
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
