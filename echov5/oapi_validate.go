// Provide HTTP middleware functionality to validate that incoming requests conform to a given OpenAPI 3.x specification.
//
// This provides middleware for an echo/v5 HTTP server.
//
// This package is a lightweight wrapper over https://pkg.go.dev/github.com/getkin/kin-openapi/openapi3filter from https://pkg.go.dev/github.com/getkin/kin-openapi.
//
// This is _intended_ to be used with code that's generated through https://pkg.go.dev/github.com/oapi-codegen/oapi-codegen, but should work otherwise.
package echomiddleware

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/labstack/echo/v5"
	echomiddleware "github.com/labstack/echo/v5/middleware"
	"github.com/oapi-codegen/echo-middleware/internal/validation"
)

// OapiValidatorFromYamlFile is an Echo middleware function which validates incoming HTTP requests
// to make sure that they conform to the given OAPI 3.0 specification. When
// OAPI validation fails on the request, we return an HTTP/400.
// Create validator middleware from a YAML file path
func OapiValidatorFromYamlFile(path string) (echo.MiddlewareFunc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %w", path, err)
	}

	spec, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s as OpenAPI YAML: %w", path, err)
	}
	return OapiRequestValidator(spec), nil
}

// OapiRequestValidator Creates the middleware to validate that incoming requests match the given OpenAPI 3.x spec, with a default set of configuration.
func OapiRequestValidator(spec *openapi3.T) echo.MiddlewareFunc {
	return OapiRequestValidatorWithOptions(spec, nil)
}

// ErrorHandler is called when there is an error in validation
type ErrorHandler func(c *echo.Context, err *echo.HTTPError) error

// MultiErrorHandler is called when the OpenAPI filter returns an openapi3.MultiError (https://pkg.go.dev/github.com/getkin/kin-openapi/openapi3#MultiError)
type MultiErrorHandler func(openapi3.MultiError) *echo.HTTPError

// Options to customize request validation. These are passed through to
// openapi3filter.
type Options struct {
	// ErrorHandler is called when a validation error occurs.
	//
	// If not provided, `http.Error` will be called
	ErrorHandler ErrorHandler
	// Options contains any configuration for the underlying `openapi3filter`
	Options openapi3filter.Options
	// ParamDecoder is the openapi3filter.ContentParameterDecoder to be used for the decoding of the request body
	//
	// If unset, a default will be used
	ParamDecoder openapi3filter.ContentParameterDecoder
	// UserData is any user-specified data to inject into the context.Context, which is then passed in to the validation function.
	//
	// Set on the Context with the key `UserDataKey`.
	UserData any
	// Skipper an echo Skipper to allow skipping the middleware.
	Skipper echomiddleware.Skipper
	// MultiErrorHandler is called when there is an openapi3.MultiError (https://pkg.go.dev/github.com/getkin/kin-openapi/openapi3#MultiError) returned by the `openapi3filter`.
	//
	// If not provided `defaultMultiErrorHandler` will be used.
	MultiErrorHandler MultiErrorHandler
	// SilenceServersWarning allows silencing a warning for https://github.com/oapi-codegen/oapi-codegen/issues/882 that reports when an OpenAPI spec has `spec.Servers != nil`
	SilenceServersWarning bool
	// DoNotValidateServers ensures that there is no Host validation performed (see `SilenceServersWarning` and https://github.com/deepmap/oapi-codegen/issues/882 for more details)
	DoNotValidateServers bool
	// Prefix is stripped from the request path before validation. This is useful when the API is mounted under a sub-path
	// (e.g. "/api") that isn't part of the OpenAPI spec's paths. The prefix must start with "/" if set.
	Prefix string
}

// OapiRequestValidatorWithOptions Creates the middleware to validate that incoming requests match the given OpenAPI 3.x spec, allowing explicit configuration.
//
// NOTE that this may panic if the OpenAPI spec isn't valid, or if it cannot be used to create the middleware
func OapiRequestValidatorWithOptions(spec *openapi3.T, options *Options) echo.MiddlewareFunc {
	if options != nil && options.DoNotValidateServers {
		spec.Servers = nil
	}

	if spec.Servers != nil && (options == nil || !options.SilenceServersWarning) {
		log.Println("WARN: OapiRequestValidatorWithOptions called with an OpenAPI spec that has `Servers` set. This may lead to an HTTP 400 with `no matching operation was found` when sending a valid request, as the validator performs `Host` header validation. If you're expecting `Host` header validation, you can silence this warning by setting `Options.SilenceServersWarning = true`. See https://github.com/oapi-codegen/oapi-codegen/issues/882 for more information.")
	}

	router, err := gorillamux.NewRouter(spec)
	if err != nil {
		panic(err)
	}

	skipper := getSkipperFromOptions(options)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if skipper(c) {
				return next(c)
			}

			err := ValidateRequestFromContext(c, router, options)
			if err != nil {
				if options != nil && options.ErrorHandler != nil {
					return options.ErrorHandler(c, err)
				}
				return err
			}
			return next(c)
		}
	}
}

// ValidateRequestFromContext validates an incoming request using the OpenAPI spec and returns an error if validation fails.
// It is called from the middleware and does the actual work of validating a request.
func ValidateRequestFromContext(c *echo.Context, router routers.Router, options *Options) *echo.HTTPError {
	req := c.Request()

	// Find the matching route
	route, pathParams, err := validation.FindRoute(req, router, getPrefix(options))
	if err != nil {
		if errors.Is(err, routers.ErrMethodNotAllowed) {
			return echo.NewHTTPError(http.StatusMethodNotAllowed, "")
		}

		switch e := err.(type) {
		case *routers.RouteError:
			// We've got a bad request, the path requested doesn't match
			// either server, or path, or something.
			return echo.NewHTTPError(http.StatusNotFound, e.Reason)
		default:
			// If our upstream code changes, we don't want to crash the server,
			// so handle the unexpected error.
			return echo.NewHTTPError(http.StatusInternalServerError,
				fmt.Sprintf("error validating route: %s", err.Error()))
		}
	}

	// Build validation context with Echo context and user data
	requestContext := context.WithValue(req.Context(), validation.EchoContextKey, c) //nolint:staticcheck
	if options != nil && options.UserData != nil {
		requestContext = context.WithValue(requestContext, validation.UserDataKey, options.UserData) //nolint:staticcheck
	}

	// Perform OpenAPI validation
	validationErr := validation.ValidateRequest(requestContext, req, route, pathParams, getFilterOptions(options), getParamDecoder(options))
	if validationErr != nil {
		if validationErr.IsMultiError {
			multiErr := validationErr.MultiErrors
			if options != nil && options.MultiErrorHandler != nil {
				return options.MultiErrorHandler(multiErr)
			}
			return defaultMultiErrorHandler(multiErr)
		}

		// Handle SecurityRequirementsError by extracting HTTPError or StatusCoder if present
		if validationErr.IsSecurityError {
			for _, err := range validationErr.SecurityErrors {
				var httpErr *echo.HTTPError
				if errors.As(err, &httpErr) {
					return httpErr
				}
				var coder interface{ StatusCode() int }
				if errors.As(err, &coder) {
					return echo.NewHTTPError(coder.StatusCode(), err.Error())
				}
			}
			// No security error matched a known structured type;
			// fall through to return the generic validation error below
		}

		return &echo.HTTPError{
			Code:    validationErr.StatusCode,
			Message: validationErr.Message,
		}
	}

	return nil
}

// GetEchoContext gets the echo context from within requests. It returns
// nil if not found or wrong type.
func GetEchoContext(c context.Context) *echo.Context {
	iface := c.Value(validation.EchoContextKey)
	if iface == nil {
		return nil
	}
	eCtx, ok := iface.(*echo.Context)
	if !ok {
		return nil
	}
	return eCtx
}

func GetUserData(c context.Context) any {
	return c.Value(validation.UserDataKey)
}

// attempt to get the skipper from the options whether it is set or not
func getSkipperFromOptions(options *Options) echomiddleware.Skipper {
	if options == nil {
		return echomiddleware.DefaultSkipper
	}

	if options.Skipper == nil {
		return echomiddleware.DefaultSkipper
	}

	return options.Skipper
}

// defaultMultiErrorHandler returns a StatusBadRequest (400) and a list
// of all of the errors. This method is called if there are no other
// methods defined on the options.
func defaultMultiErrorHandler(me openapi3.MultiError) *echo.HTTPError {
	return &echo.HTTPError{
		Code:    http.StatusBadRequest,
		Message: me.Error(),
	}
}

// getPrefix gets the prefix from options if set
func getPrefix(options *Options) string {
	if options == nil {
		return ""
	}
	return options.Prefix
}

// getFilterOptions gets the openapi3filter.Options from options if set
func getFilterOptions(options *Options) *openapi3filter.Options {
	if options == nil {
		return nil
	}
	return &options.Options
}

// getParamDecoder gets the ParamDecoder from options if set
func getParamDecoder(options *Options) openapi3filter.ContentParameterDecoder {
	if options == nil {
		return nil
	}
	return options.ParamDecoder
}
