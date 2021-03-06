package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jdxcode/netrc"
	"github.com/tjamet/local-https-dev/server/acme"
	"github.com/urfave/cli"
)

// From https://github.com/golang/go/blob/c0547476f342665514904cf2581a62135d2366c3/src/net/http/server.go#L3223
// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

type loggedResponseWriter struct {
	http.ResponseWriter
	size int
	code int
}

func (l *loggedResponseWriter) Write(b []byte) (int, error) {
	if l.code == 0 {
		l.WriteHeader(http.StatusOK)
	}
	size, err := l.ResponseWriter.Write(b)
	l.size += size
	return size, err
}

func (l *loggedResponseWriter) WriteHeader(code int) {
	l.ResponseWriter.WriteHeader(code)
	if l.code == 0 {
		l.code = code
	}
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

// ListenAndServeTLSKeyPair start a server using in-memory TLS KeyPair
func ListenAndServeTLSKeyPair(addr string, cert tls.Certificate,
	handler http.Handler) error {

	// as defined in https://github.com/golang/go/blob/c0547476f342665514904cf2581a62135d2366c3/src/net/http/server.go#L3034
	if addr == "" {
		addr = ":https"
	}
	// as defined in https://github.com/golang/go/blob/c0547476f342665514904cf2581a62135d2366c3/src/net/http/server.go#L3037
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	// if TLS config is defined, and no actual key path is provided, ServeTLS keeps the certificate
	// https://github.com/golang/go/blob/c0547476f342665514904cf2581a62135d2366c3/src/net/http/server.go#L2832
	return server.ServeTLS(ln, "", "")
}

func getCertificate(providerURL string, domain ...string) (tls.Certificate, error) {
	if len(domain) == 0 {
		domain = append(domain, "www.local.xtls.io")
	}
	body := bytes.NewReader([]byte(strings.Join(domain, " ")))
	u, err := url.Parse(providerURL)
	if err != nil {
		return tls.Certificate{}, err
	}
	u.Path = "/json"
	usr, err := user.Current()
	if err != nil {
		return tls.Certificate{}, err
	}
	n, err := netrc.Parse(filepath.Join(usr.HomeDir, ".netrc"))
	if err == nil {
		machine := n.Machine(u.Hostname())
		if machine != nil {
			u.User = url.UserPassword(machine.Get("login"), machine.Get("password"))
		}
	}

	response, err := http.Post(u.String(), "text", body)
	if err != nil {
		return tls.Certificate{}, err
	}
	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return tls.Certificate{}, err
	}
	if response.StatusCode == http.StatusUnauthorized {
		return tls.Certificate{}, fmt.Errorf("It seems that your authentication expired. Please visit https://api.xtls.io" +
			" and follow the instructions to renew your authentication")
	}
	if response.StatusCode != 200 {
		message := struct {
			Message string `json:"message"`
		}{}
		err := json.Unmarshal(b, &message)
		fmt.Println(err)
		if err != nil || message.Message == "" {
			return tls.Certificate{}, fmt.Errorf("failed to get certificate: %s", response.Status)
		}
		return tls.Certificate{}, fmt.Errorf("failed to get certificate: %s", message.Message)
	}

	certificate := acme.Certificate{}
	err = json.Unmarshal(b, &certificate)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(append(certificate.IssuerCertificate, certificate.Certificate...), certificate.PrivateKey)
}

func newProxyHandler(client *http.Client, backend *url.URL) http.Handler {
	return http.HandlerFunc(func(ow http.ResponseWriter, r *http.Request) {
		w := &loggedResponseWriter{ResponseWriter: ow}
		defer func() {
			log.Printf("%s %s %d %d Bytes", r.Method, r.URL.Path, w.code, w.size)
		}()
		req, err := http.NewRequest(r.Method, fmt.Sprintf("%s://%s", backend.Scheme, backend.Host), r.Body)
		if err != nil {
			log.Println("failed to call backend:", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		req.Host = r.Host
		// r.RequestURI contains the full value of GET http://host/path?query HTTP/1.1
		// When sending the request, request.URL.RequestURI() is used to fill GET <what> HTTP/1.1
		// Although this does not work when using proxy:
		// https://github.com/golang/go/blob/c0547476f342665514904cf2581a62135d2366c3/src/net/http/request.go#L524
		// This behaviour is achieved by providing only Opaque:
		// https://github.com/golang/go/blob/c0547476f342665514904cf2581a62135d2366c3/src/net/url/url.go#L1002
		req.URL.Opaque = r.URL.RequestURI()

		// Implement the X-Forwarded headers as defined in
		// https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html
		reqURL := url.URL{Host: r.RemoteAddr}
		req.Header.Set("X-Forwarded-Port", reqURL.Port())
		if r.TLS == nil {
			req.Header.Set("X-Forwarded-Proto", "http")
		} else {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		req.Header["X-Forwarded-For"] = []string{}
		// Forward all original request headers
		for key, value := range r.Header {
			req.Header[key] = value
		}
		req.Header["X-Forwarded-For"] = append(req.Header["X-Forwarded-For"], reqURL.Hostname())

		resp, err := client.Do(req)
		if err != nil {
			log.Println("failed to write response:", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			// Write the response back with all headers
			for key, value := range resp.Header {
				w.Header()[key] = value
			}
			w.WriteHeader(resp.StatusCode)
			_, err = io.Copy(w, resp.Body)
			if err != nil {
				log.Println("failed to write response:", err.Error())
			}
		}
	})
}

func main() {
	app := cli.NewApp()
	app.Name = "local-https-dev-proxy"
	app.Usage = "A proxy to handle HTTP TLS for localhost domains"

	app.Version = "0.0.0"

	app.Before = func(c *cli.Context) error {
		for _, key := range []string{"server", "backend"} {
			if c.String(key) == "" {
				return fmt.Errorf("missing required argument %s", key)
			}
			if len(c.StringSlice("domain")) == 0 {
				return fmt.Errorf("missing required domains to serve https on")
			}
		}
		return nil
	}

	app.Action = func(c *cli.Context) {
		backend, err := url.Parse(c.String("backend"))
		cert, err := getCertificate(c.String("server"), c.StringSlice("domain")...)
		if err != nil {
			log.Fatalf("failed to get certificate: %s", err.Error())
		}

		proxyClient := http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		tlsListen := c.StringSlice("tls")
		if len(tlsListen) == 0 {
			tlsListen = append(tlsListen, ":443")
		}
		log.Println("Starting server on ", strings.Join(tlsListen, " "), "on for domains", strings.Join(c.StringSlice("domain"), " "))
		var wg sync.WaitGroup
		for _, host := range tlsListen {
			wg.Add(1)
			go func(host string) {
				if !strings.Contains(host, ":") {
					if strings.Contains(host, ".") {
						host = host + ":443"
					} else {
						host = ":" + host
					}
				}
				err := ListenAndServeTLSKeyPair(host, cert, newProxyHandler(&proxyClient, backend))
				if strings.Contains(err.Error(), "permission denied") && len(c.StringSlice("tls")) == 0 {
					newHost := strings.Replace(host, ":443", ":4433", 1)
					log.Println("Failed to bind on ", host, "retrying on", newHost)
					host = newHost
				}
				err = ListenAndServeTLSKeyPair(host, cert, newProxyHandler(&proxyClient, backend))
				wg.Done()
				if err != nil {
					log.Fatal(err)
				}
			}(host)
		}
		wg.Wait()
	}
	app.Flags = []cli.Flag{
		cli.StringSliceFlag{
			Name:  "domain, d",
			Usage: "Add a domain to serve TLS on (default: www.local.xtls.io)",
		},
		cli.StringFlag{
			Name:  "server, s",
			Value: "https://api.xtls.io",
			Usage: "The server serving TLS certificates over HTTP (default: api.xtls.io)",
		},
		cli.StringFlag{
			Name:  "backend, b",
			Usage: "The backend to serve requests from",
		},
		cli.StringSliceFlag{
			Name:  "tls, t",
			Usage: "The TLS port to listen on (default: 0.0.0.0:443 when no listen port is provided)",
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
