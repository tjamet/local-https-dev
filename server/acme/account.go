package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"

	"github.com/pkg/errors"
	"github.com/tjamet/local-https-dev/server/cache"
	acme "github.com/xenolf/lego/acmev2"
)

// User implements the lego acme user interface to use the acme challenges
type User struct {
	Email        string
	Registration *acme.RegistrationResource
	PrivateKey   crypto.PrivateKey
	cache        cache.Cache
}

// NewUser creates a new user with a random private key
func NewUser(email string, cache cache.Cache) (*User, error) {
	b, err := cache.Get(email, "key")
	var key *rsa.PrivateKey
	if err != nil {
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}
		err = cache.Set(x509.MarshalPKCS1PrivateKey(key), 0, email, "key")
		if err != nil {
			log.Printf("failed to store private key in cache: %s", err.Error())
		}
		log.Println("generated new key for user", email)
	} else {
		key, err = x509.ParsePKCS1PrivateKey(b)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse user key")
		}
		log.Println("loaded saved key for user", email)
	}

	user := &User{
		Email:      email,
		PrivateKey: key,
		cache:      cache,
	}
	reg := acme.RegistrationResource{}
	err = cache.GetJSON(&reg, email, "registration")
	if err != nil {
		log.Printf("failed to get cached registration: %s, will re-register", err.Error())
	} else {
		log.Println("loaded registration for user", email)
		user.Registration = &reg
	}
	return user, nil
}

// GetEmail returns email
func (u *User) GetEmail() string {
	return u.Email
}

// GetRegistration returns lets encrypt registration resource
func (u *User) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

// SetRegistration sets the user lets encrypt registration and caches it
func (u *User) SetRegistration(reg *acme.RegistrationResource) error {
	u.Registration = reg
	return u.cache.SetJSON(reg, 0, u.Email, "registration")
}

// IsRegistered returns true when the user registration is already saved
func (u *User) IsRegistered() bool {
	return u.Registration != nil
}

// GetPrivateKey returns the user private key
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.PrivateKey
}
