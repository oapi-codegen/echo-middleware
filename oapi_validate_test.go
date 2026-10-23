package echomiddleware

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed test_spec.yaml
var testSchema []byte

func doGet(t *testing.T, e *echo.Echo, rawURL string) *httptest.ResponseRecorder {
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Invalid url: %s", rawURL)
	}

	r, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		t.Fatalf("Could not construct a request: %s", rawURL)
	}
	r.Header.Set("accept", "application/json")
	r.Header.Set("host", u.Host)

	tt := httptest.NewRecorder()

	e.ServeHTTP(tt, r)

	return tt
}

func doPost(t *testing.T, e *echo.Echo, rawURL string, jsonBody any) *httptest.ResponseRecorder {
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Invalid url: %s", rawURL)
	}

	body, err := json.Marshal(jsonBody)
	if err != nil {
		t.Fatalf("Could not marshal request body: %v", err)
	}

	r, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Could not construct a request for URL %s: %v", rawURL, err)
	}
	r.Header.Set("accept", "application/json")
	r.Header.Set("content-type", "application/json")
	r.Header.Set("host", u.Host)

	tt := httptest.NewRecorder()

	e.ServeHTTP(tt, r)

	return tt
}

func TestOapiRequestValidator(t *testing.T) {
	spec, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing OpenAPI spec")

	// Create a new echo router
	e := echo.New()

	// Set up an authenticator to check authenticated function. It will allow
	// access to "someScope", but disallow others.
	options := Options{
		ErrorHandler: func(c echo.Context, err *echo.HTTPError) error {
			return c.String(err.Code, "test: "+err.Error())
		},
		Options: openapi3filter.Options{
			AuthenticationFunc: func(c context.Context, input *openapi3filter.AuthenticationInput) error {
				// The echo context should be propagated into here.
				eCtx := GetEchoContext(c)
				assert.NotNil(t, eCtx)
				// As should user data
				assert.EqualValues(t, "hi!", GetUserData(c))

				for _, s := range input.Scopes {
					if s == "someScope" {
						return nil
					}
					if s == "unauthorized" {
						return echo.ErrUnauthorized
					}
				}
				return errors.New("forbidden")
			},
		},
		UserData: "hi!",
	}

	// Install our OpenApi based request validator
	e.Use(OapiRequestValidatorWithOptions(spec, &options))

	called := false

	// Install a request handler for /resource. We want to make sure it doesn't
	// get called.
	e.GET("/resource", func(c echo.Context) error {
		called = true
		return nil
	})
	// Let's send the request to the wrong server, this should return 404
	{
		rec := doGet(t, e, "http://not.test.hostname/resource")
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.False(t, called, "Handler should not have been called")
	}

	// Let's send a good request, it should pass
	{
		rec := doGet(t, e, "http://test.hostname/resource")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Send an out-of-spec parameter
	{
		rec := doGet(t, e, "http://test.hostname/resource?id=500")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Send a bad parameter type
	{
		rec := doGet(t, e, "http://test.hostname/resource?id=foo")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Send a request with the wrong HTTP method
	{
		rec := doPost(t, e, "http://test.hostname/multiparamresource", nil)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Add a handler for the POST message
	e.POST("/resource", func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusNoContent)
	})

	called = false
	// Send a good request body
	{
		body := struct {
			Name string `json:"name"`
		}{
			Name: "Marcin",
		}
		rec := doPost(t, e, "http://test.hostname/resource", body)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Send a malformed body
	{
		body := struct {
			Name int `json:"name"`
		}{
			Name: 7,
		}
		rec := doPost(t, e, "http://test.hostname/resource", body)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	e.GET("/protected_resource", func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusNoContent)
	})

	// Call a protected function to which we have access
	{
		rec := doGet(t, e, "http://test.hostname/protected_resource")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	e.GET("/protected_resource2", func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusNoContent)
	})
	// Call a protected function to which we dont have access
	{
		rec := doGet(t, e, "http://test.hostname/protected_resource2")
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	e.GET("/protected_resource_401", func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusNoContent)
	})
	// Call a protected function without credentials
	{
		rec := doGet(t, e, "http://test.hostname/protected_resource_401")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "test: code=401, message=Unauthorized", rec.Body.String())
		assert.False(t, called, "Handler should not have been called")
		called = false
	}
}

func TestOapiRequestValidatorWithOptionsMultiError(t *testing.T) {
	spec, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing OpenAPI spec")

	// Create a new echo router
	e := echo.New()

	// Set up an authenticator to check authenticated function. It will allow
	// access to "someScope", but disallow others.
	options := Options{
		Options: openapi3filter.Options{
			ExcludeRequestBody:    false,
			ExcludeResponseBody:   false,
			IncludeResponseStatus: true,
			MultiError:            true,
		},
	}

	// register middleware
	e.Use(OapiRequestValidatorWithOptions(spec, &options))

	called := false

	// Install a request handler for /resource. We want to make sure it doesn't
	// get called.
	e.GET("/multiparamresource", func(c echo.Context) error {
		called = true
		return nil
	})

	// Let's send a good request, it should pass
	{
		rec := doGet(t, e, "http://test.hostname/multiparamresource?id=50&id2=50")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Let's send a request with a missing parameter, it should return
	// a bad status
	{
		rec := doGet(t, e, "http://test.hostname/multiparamresource?id=50")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \\\"id2\\\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a 2 missing parameters, it should return
	// a bad status
	{
		rec := doGet(t, e, "http://test.hostname/multiparamresource")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \\\"id\\\"")
			assert.Contains(t, string(body), "value is required but missing")
			assert.Contains(t, string(body), "parameter \\\"id2\\\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a 1 missing parameter, and another outside
	// or the parameters. It should return a bad status
	{
		rec := doGet(t, e, "http://test.hostname/multiparamresource?id=500")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \\\"id\\\"")
			assert.Contains(t, string(body), "number must be at most 100")
			assert.Contains(t, string(body), "parameter \\\"id2\\\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a parameters that do not meet spec. It should
	// return a bad status
	{
		rec := doGet(t, e, "http://test.hostname/multiparamresource?id=abc&id2=1")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \\\"id\\\"")
			assert.Contains(t, string(body), "value abc: an invalid integer: invalid syntax")
			assert.Contains(t, string(body), "parameter \\\"id2\\\"")
			assert.Contains(t, string(body), "number must be at least 10")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}
}

func TestOapiRequestValidatorWithOptionsMultiErrorAndCustomHandler(t *testing.T) {
	spec, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing OpenAPI spec")

	// Create a new echo router
	e := echo.New()

	// Set up an authenticator to check authenticated function. It will allow
	// access to "someScope", but disallow others.
	options := Options{
		Options: openapi3filter.Options{
			ExcludeRequestBody:    false,
			ExcludeResponseBody:   false,
			IncludeResponseStatus: true,
			MultiError:            true,
		},
		MultiErrorHandler: func(me openapi3.MultiError) *echo.HTTPError {
			return &echo.HTTPError{
				Code:     http.StatusTeapot,
				Message:  me.Error(),
				Internal: me,
			}
		},
	}

	// register middleware
	e.Use(OapiRequestValidatorWithOptions(spec, &options))

	called := false

	// Install a request handler for /resource. We want to make sure it doesn't
	// get called.
	e.GET("/multiparamresource", func(c echo.Context) error {
		called = true
		return nil
	})

	// Let's send a good request, it should pass
	{
		rec := doGet(t, e, "http://test.hostname/multiparamresource?id=50&id2=50")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Let's send a request with a missing parameter, it should return
	// a bad status
	{
		rec := doGet(t, e, "http://test.hostname/multiparamresource?id=50")
		assert.Equal(t, http.StatusTeapot, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \\\"id2\\\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a 2 missing parameters, it should return
	// a bad status
	{
		rec := doGet(t, e, "http://test.hostname/multiparamresource")
		assert.Equal(t, http.StatusTeapot, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \\\"id\\\"")
			assert.Contains(t, string(body), "value is required but missing")
			assert.Contains(t, string(body), "parameter \\\"id2\\\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a 1 missing parameter, and another outside
	// or the parameters. It should return a bad status
	{
		rec := doGet(t, e, "http://test.hostname/multiparamresource?id=500")
		assert.Equal(t, http.StatusTeapot, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \\\"id\\\"")
			assert.Contains(t, string(body), "number must be at most 100")
			assert.Contains(t, string(body), "parameter \\\"id2\\\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a parameters that do not meet spec. It should
	// return a bad status
	{
		rec := doGet(t, e, "http://test.hostname/multiparamresource?id=abc&id2=1")
		assert.Equal(t, http.StatusTeapot, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \\\"id\\\"")
			assert.Contains(t, string(body), "value abc: an invalid integer: invalid syntax")
			assert.Contains(t, string(body), "parameter \\\"id2\\\"")
			assert.Contains(t, string(body), "number must be at least 10")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}
}

func TestOapiRequestValidatorWithPrefix(t *testing.T) {
	spec, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing OpenAPI spec")

	// Create a new echo router
	e := echo.New()

	options := Options{
		SilenceServersWarning: true,
		Prefix:                "/api",
	}

	// Install our OpenApi based request validator
	e.Use(OapiRequestValidatorWithOptions(spec, &options))

	called := false

	type testBody struct {
		Msg string
	}

	// Register handler under the prefixed path (as echo sees it)
	e.GET("/api/resource", func(c echo.Context) error {
		called = true
		// The original request path should be preserved for the handler
		assert.Equal(t, "/api/resource", c.Request().URL.Path)
		return c.NoContent(http.StatusOK)
	})
	e.POST("/api/resource", func(c echo.Context) error {
		called = true
		// The original request path should be preserved for the handler
		assert.Equal(t, "/api/resource", c.Request().URL.Path)
		req := c.Request()
		data, err := io.ReadAll(req.Body)
		require.NoError(t, err, "Reading POST body")
		assert.Equal(t, "{\"Msg\":\"testbody\"}", string(data))
		return c.NoContent(http.StatusOK)
	})

	// A request to /api/resource should validate against /resource in the spec
	{
		rec := doGet(t, e, "http://test.hostname/api/resource")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// A POST request to /api/resource should validate against /resource in the spec and have a specific body
	{
		rec := doPost(t, e, "http://test.hostname/api/resource", testBody{
			Msg: "testbody",
		})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// A request with query params should also validate correctly
	{
		rec := doGet(t, e, "http://test.hostname/api/resource?id=50")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// An out-of-spec parameter should still be rejected
	{
		rec := doGet(t, e, "http://test.hostname/api/resource?id=500")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
	}
}

// prefixSpec is used by the Options.Prefix tests below. It has no servers, so
// no Host validation is performed.
const prefixSpec = `
openapi: "3.0.0"
info:
  title: prefix
  version: 1.0.0
paths:
  /thing:
    post:
      operationId: createThing
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name:
                  type: string
      responses:
        '204':
          description: ok
  /defaulted:
    post:
      operationId: createDefaulted
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                count:
                  type: integer
                  default: 7
      responses:
        '204':
          description: ok
  /items/{id}:
    get:
      operationId: getItem
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            pattern: '^[a-z]/[a-z]$'
      responses:
        '204':
          description: ok
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
`

func loadPrefixSpec(t *testing.T) *openapi3.T {
	t.Helper()
	spec, err := openapi3.NewLoader().LoadFromData([]byte(prefixSpec))
	require.NoError(t, err, "Error initializing OpenAPI spec")
	return spec
}

// TestPrefixWithSecurityKeepsRequestBody covers issue #49: with a Prefix and
// a security requirement, openapi3filter reads the body for the
// AuthenticationFunc and for body validation, and the handler must still get
// the complete body, a matching ContentLength and the original path.
func TestPrefixWithSecurityKeepsRequestBody(t *testing.T) {
	spec := loadPrefixSpec(t)
	e := echo.New()

	const body = `{"name":"x"}`

	authCalled := false
	e.Use(OapiRequestValidatorWithOptions(spec, &Options{
		Prefix: "/api",
		Options: openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
				authCalled = true
				// The prefix is trimmed in place on the live request during
				// validation, so the echo request seen here has the trimmed path.
				assert.Equal(t, "/thing", GetEchoContext(ctx).Request().URL.Path)

				// The AuthenticationFunc can read the body too.
				data, err := io.ReadAll(input.RequestValidationInput.Request.Body)
				require.NoError(t, err)
				assert.Equal(t, body, string(data))

				if input.RequestValidationInput.Request.Header.Get("Authorization") != "Bearer token" {
					return echo.ErrUnauthorized
				}
				return nil
			},
		},
	}))

	var (
		called  bool
		gotBody []byte
		gotLen  int64
		gotPath string
	)
	e.POST("/api/thing", func(c echo.Context) error {
		called = true
		req := c.Request()
		gotPath = req.URL.Path
		gotLen = req.ContentLength
		var err error
		gotBody, err = io.ReadAll(req.Body)
		require.NoError(t, err)
		return c.NoContent(http.StatusNoContent)
	})

	newRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/thing", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return r
	}

	// Authorized: the handler sees the exact body, its length and the
	// original, untrimmed path.
	{
		r := newRequest()
		r.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, r)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, authCalled, "AuthenticationFunc should have been called")
		assert.True(t, called, "Handler should have been called")
		assert.Equal(t, body, string(gotBody))
		assert.Equal(t, int64(len(body)), gotLen)
		assert.Equal(t, "/api/thing", gotPath)
		assert.Equal(t, "/api/thing", r.URL.Path)
	}

	// Unauthorized: the handler must not run, and the path is still restored.
	{
		authCalled, called = false, false
		r := newRequest()
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, r)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.True(t, authCalled, "AuthenticationFunc should have been called")
		assert.False(t, called, "Handler should not have been called")
		assert.Equal(t, "/api/thing", r.URL.Path)
	}
}

// TestPrefixKeepsRewrittenBody checks that when openapi3filter applies schema
// defaults and rewrites the body, the handler gets the rewritten body with a
// ContentLength that matches it.
func TestPrefixKeepsRewrittenBody(t *testing.T) {
	spec := loadPrefixSpec(t)
	e := echo.New()
	e.Use(OapiRequestValidatorWithOptions(spec, &Options{Prefix: "/api"}))

	var (
		called  bool
		gotBody []byte
		gotLen  int64
	)
	e.POST("/api/defaulted", func(c echo.Context) error {
		called = true
		gotLen = c.Request().ContentLength
		var err error
		gotBody, err = io.ReadAll(c.Request().Body)
		require.NoError(t, err)
		return c.NoContent(http.StatusNoContent)
	})

	const body = `{"name":"x"}`
	r := httptest.NewRequest(http.MethodPost, "/api/defaulted", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.True(t, called, "Handler should have been called")
	assert.JSONEq(t, `{"name":"x","count":7}`, string(gotBody))
	assert.Equal(t, int64(len(gotBody)), gotLen, "ContentLength should match the rewritten body")
	assert.NotEqual(t, int64(len(body)), gotLen, "ContentLength should not be the original length")
}

// TestPrefixKeepValidatedValue checks that the body wrapper set by
// openapi3filter.Options.KeepValidatedValue reaches the handler.
func TestPrefixKeepValidatedValue(t *testing.T) {
	spec := loadPrefixSpec(t)
	e := echo.New()
	e.Use(OapiRequestValidatorWithOptions(spec, &Options{
		Prefix: "/api",
		Options: openapi3filter.Options{
			KeepValidatedValue: true,
		},
	}))

	called := false
	e.POST("/api/defaulted", func(c echo.Context) error {
		called = true
		vv, ok := c.Request().Body.(interface{ ValidatedValue() any })
		if assert.True(t, ok, "request body should implement ValidatedValue(), got %T", c.Request().Body) {
			value, isMap := vv.ValidatedValue().(map[string]any)
			if assert.True(t, isMap, "validated value should be a map, got %T", vv.ValidatedValue()) {
				assert.Equal(t, "x", value["name"])
				assert.Contains(t, value, "count", "validated value should include the default")
			}
		}
		data, err := io.ReadAll(c.Request().Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"name":"x","count":7}`, string(data))
		return c.NoContent(http.StatusNoContent)
	})

	r := httptest.NewRequest(http.MethodPost, "/api/defaulted", strings.NewReader(`{"name":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.True(t, called, "Handler should have been called")
}

// TestKeepValidatedValueDefault checks that openapi3filter's
// KeepValidatedValue is enabled by default, so the handler's request body
// exposes the validated value, that DiscardValidatedValue turns it off, and
// that the caller's Options are not modified.
func TestKeepValidatedValueDefault(t *testing.T) {
	const body = `{"name":"Marcin"}`

	tests := []struct {
		name    string
		options *Options // nil means OapiRequestValidator(spec)
		// wantValue is whether the handler's body should implement
		// ValidatedValue().
		wantValue bool
	}{
		{
			name:      "no options",
			wantValue: true,
		},
		{
			name:      "empty options",
			options:   &Options{},
			wantValue: true,
		},
		{
			name:      "DiscardValidatedValue",
			options:   &Options{DiscardValidatedValue: true},
			wantValue: false,
		},
		{
			name: "DiscardValidatedValue overrides openapi3filter KeepValidatedValue",
			options: &Options{
				DiscardValidatedValue: true,
				Options:               openapi3filter.Options{KeepValidatedValue: true},
			},
			wantValue: false,
		},
		{
			// The body is not validated, so there is no validated value to
			// keep, but the request must still go through untouched.
			name: "ExcludeRequestBody",
			options: &Options{
				Options: openapi3filter.Options{ExcludeRequestBody: true},
			},
			wantValue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := openapi3.NewLoader().LoadFromData(testSchema)
			require.NoError(t, err, "Error initializing OpenAPI spec")

			var callerOpts openapi3filter.Options
			e := echo.New()
			if tt.options == nil {
				e.Use(OapiRequestValidator(spec))
			} else {
				tt.options.SilenceServersWarning = true
				callerOpts = tt.options.Options
				e.Use(OapiRequestValidatorWithOptions(spec, tt.options))
			}

			called := false
			e.POST("/resource", func(c echo.Context) error {
				called = true
				vv, ok := c.Request().Body.(interface{ ValidatedValue() any })
				if tt.wantValue {
					if assert.True(t, ok, "request body should implement ValidatedValue(), got %T", c.Request().Body) {
						assert.Equal(t, map[string]any{"name": "Marcin"}, vv.ValidatedValue())
					}
				} else {
					assert.False(t, ok, "request body should not implement ValidatedValue(), got %T", c.Request().Body)
				}
				data, err := io.ReadAll(c.Request().Body)
				require.NoError(t, err)
				assert.Equal(t, body, string(data))
				return c.NoContent(http.StatusNoContent)
			})

			r := httptest.NewRequest(http.MethodPost, "http://test.hostname/resource", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, r)

			assert.Equal(t, http.StatusNoContent, rec.Code)
			assert.True(t, called, "Handler should have been called")
			if tt.options != nil {
				assert.Equal(t, callerOpts.KeepValidatedValue, tt.options.Options.KeepValidatedValue,
					"the caller's openapi3filter.Options should not be modified")
			}
		})
	}
}

// TestPrefixEncodedPathParams checks that a percent-encoded path parameter
// still routes under a Prefix: URL.RawPath must be trimmed along with
// URL.Path, and both restored for the handler.
func TestPrefixEncodedPathParams(t *testing.T) {
	spec := loadPrefixSpec(t)
	e := echo.New()
	e.Use(OapiRequestValidatorWithOptions(spec, &Options{Prefix: "/api"}))

	var (
		called     bool
		gotPath    string
		gotRawPath string
	)
	e.GET("/api/items/:id", func(c echo.Context) error {
		called = true
		gotPath = c.Request().URL.Path
		gotRawPath = c.Request().URL.RawPath
		return c.NoContent(http.StatusNoContent)
	})

	// %2F decodes to "/", so the parameter is "a/b", which matches the
	// pattern. Without trimming RawPath, the router would see the decoded
	// path /items/a/b and find no route.
	{
		rec := doGet(t, e, "http://test.hostname/api/items/a%2Fb")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called, "Handler should have been called")
		assert.Equal(t, "/api/items/a/b", gotPath)
		assert.Equal(t, "/api/items/a%2Fb", gotRawPath)
		called = false
	}

	// A value that does not match the pattern is still rejected.
	{
		rec := doGet(t, e, "http://test.hostname/api/items/ab")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
	}
}

func TestEncodedPathParams(t *testing.T) {
	spec, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing OpenAPI spec")

	e := echo.New()

	options := Options{
		SilenceServersWarning: true,
	}

	e.Use(OapiRequestValidatorWithOptions(spec, &options))

	called := false

	// Register handlers for parameterized paths. These must be registered
	// before any requests are made so echo allocates enough param slots.
	e.GET("/resource/maxlength/:param", func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusNoContent)
	})
	e.GET("/resource/pattern/:param", func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusNoContent)
	})

	// Encoded "+" (%2B) — 3 chars encoded, but 1 char decoded.
	// maxLength: 1 should pass because validation uses the decoded value.
	{
		rec := doGet(t, e, "http://test.hostname/resource/maxlength/%2B")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Unencoded "+" in the same path — should also pass.
	{
		rec := doGet(t, e, "http://test.hostname/resource/maxlength/+")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Two-char unencoded value exceeds maxLength: 1 — should be rejected.
	{
		rec := doGet(t, e, "http://test.hostname/resource/maxlength/ab")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
	}

	// Encoded value that decodes to two chars (%2B%2B -> "++") — should be rejected.
	{
		rec := doGet(t, e, "http://test.hostname/resource/maxlength/%2B%2B")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
	}

	// Pattern: ^\+[0-9]+$ — encoded "+1234" as "%2B1234" should pass.
	{
		rec := doGet(t, e, "http://test.hostname/resource/pattern/%2B1234")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Unencoded "+1234" should also pass.
	{
		rec := doGet(t, e, "http://test.hostname/resource/pattern/+1234")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Value that doesn't match pattern — should be rejected.
	{
		rec := doGet(t, e, "http://test.hostname/resource/pattern/nope")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
	}
}

func TestGetSkipperFromOptions(t *testing.T) {
	options := new(Options)
	assert.NotNil(t, getSkipperFromOptions(options))

	options = &Options{}
	assert.NotNil(t, getSkipperFromOptions(options))

	options = &Options{
		Skipper: echomiddleware.DefaultSkipper,
	}
	assert.NotNil(t, getSkipperFromOptions(options))
}
