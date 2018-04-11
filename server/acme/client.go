package acme

import (
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/tjamet/local-https-dev/server/cache"
	acme "github.com/xenolf/lego/acmev2"
	"github.com/xenolf/lego/providers/dns"
)

// Client is a let's encrypt client
type Client struct {
	client *acme.Client
	cache  cache.Cache
}

// Certificate holds all requirements to configure the full chain certificate
type Certificate struct {
	IssuerCertificate []byte `json:"issuer-certificate"`
	Certificate       []byte `json:"certificate"`
	PrivateKey        []byte `json:"private-key"`
}

func computeCacheKey(values ...string) string {
	values = append([]string{}, values...)
	sort.Sort(sort.StringSlice(values))
	cacheKey := strings.Replace(strings.Join(values, ","), "*", "-", -1)
	return strings.Replace(strings.Replace(cacheKey, "//", "", 1), "/", "-", -1)
}

// New creates a new acme client
func New(logger *log.Logger, email, dnsProvider, caServer string, cache cache.Cache) (*Client, error) {
	acme.Logger = logger

	// remove protocol from cache key
	URL, err := url.Parse(caServer)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse acme server URL")
	}
	URL.Scheme = ""
	cache.Prefix(computeCacheKey(URL.String()))

	user, err := NewUser(email, cache.Clone().Prefix("account"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create acme user")
	}

	client, err := acme.NewClient(caServer, user, acme.RSA4096)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create lego client")
	}
	provider, err := dns.NewDNSChallengeProviderByName(dnsProvider)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create challenge provider %s", dnsProvider)
	}
	client.ExcludeChallenges([]acme.Challenge{acme.HTTP01})
	err = client.SetChallengeProvider(acme.DNS01, provider)
	if err != nil {
		return nil, errors.Wrap(err, "failed to assign lego challenge provider")
	}
	if !user.IsRegistered() {
		log.Println("registering new user", email)
		reg, err := client.Register(true)
		if err != nil {
			return nil, errors.Wrap(err, "failed to register acme client")
		}
		user.SetRegistration(reg)
	}

	return &Client{
		client: client,
		cache:  cache.Clone().Prefix("certificates"),
	}, nil
}

// GetCertificate returns the all certificates and keys for future use (dump as JSON, ...)
func (c *Client) GetCertificate(domain ...string) (*Certificate, error) {
	cert := Certificate{}
	sortedDomain := append([]string{}, domain...)
	sort.Sort(sort.StringSlice(sortedDomain))
	cacheKey := computeCacheKey(domain...)
	err := c.cache.GetJSON(&cert, cacheKey)
	if err != nil {
		log.Println("getting new certificate for domains", strings.Join(domain, " "))
		certificates, failures := c.client.ObtainCertificate(domain, false, nil, false)
		if len(failures) > 0 {
			msg := "failed to optain certificate:"
			for key, value := range failures {
				msg = fmt.Sprintf("%s %s: %s", msg, key, value)
			}
			return nil, fmt.Errorf(msg)
		}
		cert = Certificate{
			IssuerCertificate: certificates.IssuerCertificate,
			Certificate:       certificates.Certificate,
			PrivateKey:        certificates.PrivateKey,
		}
		c.cache.SetJSON(cert, 25*24*time.Hour, cacheKey)
	} else {
		log.Println("retrieved certificate for domain", strings.Join(domain, " "), "from cache")
	}
	return &cert, nil
}
