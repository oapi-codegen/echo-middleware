// Package validation provides framework-agnostic OpenAPI request validation logic.
//
// This package contains the core validation logic that's independent of the Echo framework version.
// It validates incoming HTTP requests against an OpenAPI 3.x specification.
package validation

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
)

const (
	EchoContextKey = "oapi-codegen/echo-context"
	UserDataKey    = "oapi-codegen/user-data"
)

// RequestValidationError represents an OpenAPI validation error
type RequestValidationError struct {
	// StatusCode is the HTTP status code for this error
	StatusCode int
	// Message is a human-readable error message
	Message string
	// Internal is the underlying error
	Internal error
	// IsMultiError indicates if this is a MultiError
	IsMultiError bool
	// MultiErrors contains the multi-error if IsMultiError is true
	MultiErrors openapi3.MultiError
	// ErrorLines contains split error message lines
	ErrorLines []string
	// IsSecurityError indicates if this is a SecurityRequirementsError
	IsSecurityError bool
	// SecurityErrors contains the inner errors from SecurityRequirementsError
	SecurityErrors []error
}

// FindRoute finds the matching route for a request, with optional prefix stripping
func FindRoute(req *http.Request, router routers.Router, prefix string) (*routers.Route, map[string]string, error) {
	// Apply prefix stripping if needed
	if prefix != "" {
		clone := req.Clone(req.Context())
		clone.URL.Path = strings.TrimPrefix(clone.URL.Path, prefix)
		req = clone
	}

	return router.FindRoute(req)
}

// ValidateRequest validates an HTTP request against a matched route.
// It returns nil if validation passes, or a RequestValidationError if it fails.
// The context should have EchoContextKey and UserDataKey set by the caller.
func ValidateRequest(ctx context.Context, req *http.Request, route *routers.Route, pathParams map[string]string, options *openapi3filter.Options, paramDecoder openapi3filter.ContentParameterDecoder) *RequestValidationError {
	// gorillamux uses UseEncodedPath(), so path parameters are returned in
	// their percent-encoded form. Unescape them before passing to
	// openapi3filter, which expects decoded values.
	for k, v := range pathParams {
		if unescaped, err := url.PathUnescape(v); err == nil {
			pathParams[k] = unescaped
		}
	}

	// Build validation input
	validationInput := &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: pathParams,
		Route:      route,
	}

	if options != nil {
		validationInput.Options = options
	}

	if paramDecoder != nil {
		validationInput.ParamDecoder = paramDecoder
	}

	// Perform validation
	err := openapi3filter.ValidateRequest(ctx, validationInput)
	if err == nil {
		return nil // validation passed
	}

	// Handle MultiError
	me := openapi3.MultiError{}
	if errors.As(err, &me) {
		return &RequestValidationError{
			StatusCode:   http.StatusBadRequest,
			Message:      me.Error(),
			Internal:     me,
			IsMultiError: true,
			MultiErrors:  me,
		}
	}

	// Handle RequestError
	if re, ok := err.(*openapi3filter.RequestError); ok {
		errorLines := strings.Split(re.Error(), "\n")
		return &RequestValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    errorLines[0],
			Internal:   err,
			ErrorLines: errorLines,
		}
	}

	// Handle SecurityRequirementsError
	if sre, ok := err.(*openapi3filter.SecurityRequirementsError); ok {
		return &RequestValidationError{
			StatusCode:      http.StatusForbidden,
			Message:         sre.Error(),
			Internal:        err,
			IsSecurityError: true,
			SecurityErrors:  sre.Errors,
		}
	}

	// Handle unknown error
	return &RequestValidationError{
		StatusCode: http.StatusInternalServerError,
		Message:    "error validating request: " + err.Error(),
		Internal:   err,
	}
}
