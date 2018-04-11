package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

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
	if c.String("domain") != "" && domains != nil {
		for _, domain := range domains {
			if !strings.HasSuffix(domain, c.String("domain")) {
				return nil, fmt.Errorf("all requested domains should end with %s", c.String("domain"))
			}
		}
	}
	return client.GetCertificate(domains...)
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
	fmt.Println(path)
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
	app.Name = "local-https-server"
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
		cli.BoolFlag{
			Name:  "accept-tos, a",
			Usage: "By setting this flag to true you indicate that you accept the current Let's Encrypt terms of service.",
		},
		cli.UintFlag{
			Name:  "port, p",
			Value: 8080,
			Usage: "The port the server should listen to.",
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
