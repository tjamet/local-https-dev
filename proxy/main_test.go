package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandler(t *testing.T) {
	test := func(host, hostInURL, expectedProto, expectedHost string) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/something?a=3&b=4", r.URL.String())
			assert.Equal(t, expectedHost, r.Host)
			assert.Equal(t, []string{expectedProto}, r.Header["X-Forwarded-Proto"])
			assert.Equal(t, []string{"167.0.0.1"}, r.Header["X-Forwarded-For"])
			assert.Equal(t, []string{"_"}, r.Header["Test"])
			w.Header().Set("new", "value")
			w.WriteHeader(898)
			w.Write([]byte("body"))
		}))
		r := httptest.NewRequest("GET", host+"/something?a=3&b=4", nil)
		if hostInURL != "" {
			r.URL.Host = hostInURL
			r.URL.Scheme = expectedProto
		}
		r.Header.Set("test", "_")
		r.RemoteAddr = "167.0.0.1:1254"
		w := httptest.NewRecorder()
		u, err := url.Parse(s.URL)
		assert.NoError(t, err)
		newProxyHandler(http.DefaultClient, u).ServeHTTP(w, r)
		assert.Equal(t, []string{"value"}, w.Result().Header["New"])
		assert.Equal(t, "body", w.Body.String())
	}
	test("https://example.com", "example.com", "https", "example.com")
	test("http://example.com", "example.com", "http", "example.com")
	test("http://example.co", "", "http", "example.co")
}
