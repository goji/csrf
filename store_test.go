package csrf

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/zenazn/goji/web"
)

// Check Store implementations
var _ store = &cookieStore{}

// brokenSaveStore is a CSRF store that cannot, well, save.
type brokenSaveStore struct {
	store
}

func (bs *brokenSaveStore) Get(*web.C, *http.Request) ([]byte, error) {
	// Generate an invalid token so we can progress to our Save method
	return generateRandomBytes(24)
}

func (bs *brokenSaveStore) Save(realToken []byte, w http.ResponseWriter) error {
	return errors.New("test error")
}

// Tests for failure if the middleware can't save to the Store.
func TestStoreCannotSave(t *testing.T) {
	s := web.New()
	bs := &brokenSaveStore{}
	s.Use(Protect(testKey, setStore(bs)))
	s.Get("/", testHandler)

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("broken store did not set an error status: got %v want %v",
			rr.Code, http.StatusForbidden)
	}

	if c := rr.Header().Get("Set-Cookie"); c != "" {
		t.Fatalf("broken store incorrectly set a cookie: got %v want %v",
			c, "")
	}

}

// TestCookieDecode tests that an invalid cookie store returns a decoding error.
func TestCookieDecode(t *testing.T) {
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	var age = 3600

	// Test with a nil hash key
	sc := securecookie.New(nil, nil)
	sc.MaxAge(age)
	st := &cookieStore{cookieName, age, sc}

	// Set a fake cookie value so r.Cookie passes.
	r.Header.Set("Cookie", fmt.Sprintf("%s=%s", cookieName, "notacookie"))

	_, err = st.Get(&web.C{}, r)
	if err == nil {
		t.Fatal("cookiestore did not report an invalid hashkey on decode")
	}
}

// TestCookieEncode tests that an invalid cookie store returns an encoding error.
func TestCookieEncode(t *testing.T) {
	var age = 3600

	// Test with a nil hash key
	sc := securecookie.New(nil, nil)
	sc.MaxAge(age)
	st := &cookieStore{cookieName, age, sc}

	rr := httptest.NewRecorder()

	err := st.Save(nil, rr)
	if err == nil {
		t.Fatal("cookiestore did not report an invalid hashkey on encode")
	}
}
