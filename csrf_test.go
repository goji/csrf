package csrf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zenazn/goji/web"
)

var testKey = []byte("keep-it-secret-keep-it-safe-----")
var testHandler = web.HandlerFunc(func(c web.C, w http.ResponseWriter, r *http.Request) {})

// TestProtect is a high-level test to make sure the middleware returns the
// wrapped handler with a 200 OK status.
func TestProtect(t *testing.T) {
	s := web.New()
	s.Use(Protect(testKey))

	s.Get("/", testHandler)

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}
}

// Test that idempotent methods return a 200 OK status and that non-idempotent
// methods return a 403 Forbidden status when a CSRF cookie is not present.
func TestMethods(t *testing.T) {
	s := web.New()
	s.Use(Protect(testKey))

	s.Handle("/", web.HandlerFunc(func(c web.C, w http.ResponseWriter, r *http.Request) {
	}))

	// Test idempontent ("safe") methods
	for _, method := range safeMethods {
		r, err := http.NewRequest(method, "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, r)

		if rr.Code != http.StatusOK {
			t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
				rr.Code, http.StatusOK)
		}

		if rr.Header().Get("Set-Cookie") == "" {
			t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
		}
	}

	// Test non-idempotent methods (should return a 403 without a cookie set)
	nonIdempotent := []string{"POST", "PUT", "DELETE", "PATCH"}
	for _, method := range nonIdempotent {
		r, err := http.NewRequest(method, "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, r)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
				rr.Code, http.StatusOK)
		}

		if rr.Header().Get("Set-Cookie") == "" {
			t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
		}
	}

}

// Tests for failure if the cookie containing the session is removed from the
// request.
func TestNoCookie(t *testing.T) {

}

// TestBadCookie tests for failure when a cookie header is modified (malformed).
func TestBadCookie(t *testing.T) {
	s := web.New()
	CSRF := Protect(testKey)
	s.Use(CSRF)

	var token string
	s.Handle("/", web.HandlerFunc(func(c web.C, w http.ResponseWriter, r *http.Request) {
		token = Token(c, r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Replace the cookie prefix
	badHeader := strings.Replace("_csrfToken=", rr.Header().Get("Set-Cookie"), "_badCookie", -1)
	r.Header.Set("Cookie", badHeader)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Referer", "http://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to reject a bad cookie: got %v want %v",
			rr.Code, http.StatusForbidden)
	}

}

// Responses should set a "Vary: Cookie" header to protect client/proxy caching.
func TestVaryHeader(t *testing.T) {

	s := web.New()
	s.Use(Protect(testKey))
	s.Get("/", testHandler)

	r, err := http.NewRequest("HEAD", "https://www.golang.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Vary") != "Cookie" {
		t.Fatalf("vary header not set: got %q want %q", rr.Header().Get("Vary"), "Cookie")
	}
}

// Requests with no Referer header should fail.
func TestNoReferer(t *testing.T) {

	s := web.New()
	s.Use(Protect(testKey))
	s.Handle("/", web.HandlerFunc(func(c web.C, w http.ResponseWriter, r *http.Request) {}))

	r, err := http.NewRequest("POST", "https://golang.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestBadReferer checks that HTTPS requests with a Referer that does not
// match the request URL correctly fail CSRF validation.
func TestBadReferer(t *testing.T) {

	s := web.New()
	CSRF := Protect(testKey)
	s.Use(CSRF)

	var token string
	s.Handle("/", web.HandlerFunc(func(c web.C, w http.ResponseWriter, r *http.Request) {
		token = Token(c, r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "https://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "https://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)

	// Set a non-matching Referer header.
	r.Header.Set("Referer", "http://goji.io")

	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// Requests with a valid Referer should pass.
func TestWithReferer(t *testing.T) {
	s := web.New()
	CSRF := Protect(testKey)
	s.Use(CSRF)

	var token string
	s.Handle("/", web.HandlerFunc(func(c web.C, w http.ResponseWriter, r *http.Request) {
		token = Token(c, r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Referer", "http://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	t.Log(r.Header)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}
}

// TestFormField tests that a token in the form field takes precedence over a
// token in the HTTP header.
func TestFormField(t *testing.T) {

}

func setCookie(rr *httptest.ResponseRecorder, r *http.Request) {
	r.Header.Set("Cookie", rr.Header().Get("Set-Cookie"))
}
