# goji/csrf
[![GoDoc](https://godoc.org/github.com/goji/csrf?status.svg)](https://godoc.org/github.com/goji/csrf) [![Build Status](https://travis-ci.org/goji/csrf.svg?branch=master)](https://travis-ci.org/goji/csrf)

goji/csrf is a HTTP middleware library that provides [cross-site request
forgery](http://blog.codinghorror.com/preventing-csrf-and-xsrf-attacks/) (CSRF)
 protection. It includes:

* The `csrf.Protect` middleware/handler that can be used with `goji.Use` to 
  provide CSRF protection on routes attached to a router or a sub-router.
* A `csrf.Token` function that provides the token to pass into your response,
  whether that be a HTML form or a JSON response body.
* ... and a `csrf.TemplateField` helper that you can pass into your `html/template`
  templates to replace a `{{ .csrfField }}` template tag with a hidden input
  field. 

This library is designed to work with the [Goji](https://github.com/zenazn/goji)
micro-framework, which is a simple web framework for Go that is broadly
compatible with other parts of the Go ecosystem. It makes use of Goji's `web.C` 
request context, which doesn't rely on a global map, and is therefore safe to 
attach to your top-level router (if you so wish).

The library also assumes HTTPS by default: sending cookies over vanilla HTTP 
is risky and you're likely to get hurt. 

## Examples

goji/csrf is easy to use: add the middleware to your stack with the below:

```go
goji.Use(csrf.Protect([]byte("32-byte-long-auth-key")))
```

... and then collect the token with `csrf.Token(c, r)` before passing it to the 
template, JSON body or HTTP header (you pick!). goji/csrf inspects the form body 
(first) and HTTP headers (second) on subsequent POST/PUT/PATCH/DELETE/etc. requests 
for the token.

### HTML Forms

Here's the common use-case: HTML forms you want to provide CSRF protection for, 
in order to protect malicious POST requests being made:

```go
package main

import (
    "github.com/goji/csrf"
    "github.com/zenazn/goji"
)

func main() {
    // Add the middleware to your router.
    goji.Use(csrf.Protect([]byte("32-byte-long-auth-key")))
    goji.Get("/signup", ShowSignupForm)
    // POST requests without a valid token will return a HTTP 403 Forbidden.
    goji.Post("/signup/post", SubmitSignupForm)

    goji.Serve()
}

func ShowSignupForm(c web.C, w http.ResponseWriter, r *http.Request) {
    // signup_form.tmpl just needs a {{ .csrfField }} template tag for
    // csrf.TemplateField to inject the CSRF token into. Easy!
    t.ExecuteTemplate(w, "signup_form.tmpl", map[string]interface{
        csrf.TemplateTag: csrf.TemplateField(c, r),
    })
    // We could also retrieve the token directly from csrf.Token(c, r) and 
    // set it in the request header - w.Header.Set("X-CSRF-Token", token)
    // This is useful if your sending JSON to clients or a front-end JavaScript
    // framework.
}

func SubmitSignupForm(c web.C, w http.ResponseWriter, r *http.Request) {
    // We can trust that requests making it this far have satisfied
    // our CSRF protection requirements.
}
```

### JSON Responses

This approach is useful if you're using a front-end JavaScript framework like 
Ember or Angular, or are providing a JSON API.

We'll also look at applying selective CSRF protection using Goji's sub-routers, 
as we don't handle any POST/PUT/DELETE requests with our top-level router.

```go
package main

import (
    "github.com/goji/csrf"
    "github.com/zenazn/goji/graceful"
    "github.com/zenazn/goji/web"
)

func main() {
    r := web.New()
    // Our top-level router doesn't need CSRF protection: it's simple.
    r.Get("/", ShowIndex)

    api := web.New()
    r.Handle("/api/*", s)
    // ... but our /api/* routes do, so we add it to the sub-router only.
    s.Use(csrf.Protect([]byte("32-byte-long-auth-key")))

    s.Get("/api/user/:id", GetUser)
    s.Post("/api/user", PostUser)

    graceful.ListenAndServe(":8000", r)
}

func GetUser(c web.C, w http.ResponseWriter, r *http.Request) {
    // Authenticate the request, get the :id from the route params, 
    // and fetch the user from the DB, etc.

    // Get the token and pass it in the CSRF header. Our JSON-speaking client 
    // or JavaScript framework can now read the header and return the token in 
    // in its own "X-CSRF-Token" request header on the subsequent POST.
    w.Header().Set("X-CSRF-Token", csrf.Token(c, r))
    b, err := json.Marshal(user)
    if err != nil {
        http.Error(...)
        return
    }

    w.Write(b)
}
```

### Setting Options

What about providing your own error handler and changing the HTTP header the
package inspects on requests? (i.e. an existing API you're porting to Go). Well, 
goji/csrf provides options for changing these as you see fit:

```go
func main() {
    CSRF := csrf.Protect(
            []byte("a-32-byte-long-key-goes-here"),
            csrf.RequestHeader("Authenticity-Token"),
            csrf.FieldName("authenticity_token"),
            // Note that csrf.ErrorHandler takes a Goji web.Handler type, else 
            // your error handler can't retrieve the error reason from the context.
            // The signature `func UnauthHandler(c web.C, w http.ResponseWriter, r *http.Request)`
            // is a web.Handler, and the simplest to use if you'd like to serve
            // "pretty" error pages (who doesn't?).
            csrf.ErrorHandler(web.HandlerFunc(serverError(403))),
        )

    goji.Use(CSRF)
    goji.Get("/signup", GetSignupForm)
    goji.Post("/signup", PostSignupForm)

    goji.Serve()
}
```

Not too bad, right?

If there's something you're confused about or a feature you would like to see
added, open an issue with your code so far.

## Design Notes

Getting CSRF protection right is important, so here's some background:

* This library generates unique-per-request (masked) tokens as a mitigation
  against the [BREACH attack](http://breachattack.com/).
* The 'base' (unmasked) token is stored in the session, which means that
  multiple browser tabs won't cause a user problems as their per-request token
  is compared with the base token.
* Operates on a "whitelist only" approach where safe (non-mutating) HTTP methods
  (GET, HEAD, OPTIONS, TRACE) are the *only* methods where token validation is not
  enforced.
* The design is based on the battle-tested
  [Django](https://docs.djangoproject.com/en/1.8/ref/csrf/) and [Ruby on
  Rails](http://api.rubyonrails.org/classes/ActionController/RequestForgeryProtection.html)
  approaches.
* Cookies are authenticated and based on the [securecookie](https://github.com/gorilla/securecookie)
  library. They're also Secure (issued over HTTPS only) and are HttpOnly
  by default, because sane defaults are important.
* Go's `crypto/rand` library is used to generate the 32 byte (256 bit) tokens 
  and the one-time-pad used for masking them.

This library does not seek to be adventurous.

## License

BSD licensed. See the LICENSE file for details.

