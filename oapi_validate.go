// Provide HTTP middleware functionality to validate that incoming requests conform to a given OpenAPI 3.x specification.
//
// This provides middleware for an echo/v4 HTTP server.
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
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
)

const (
	EchoContextKey = "oapi-codegen/echo-context"
	UserDataKey    = "oapi-codegen/user-data"
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
type ErrorHandler func(c echo.Context, err *echo.HTTPError) error

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
		return func(c echo.Context) error {
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

// ValidateRequestFromContext is called from the middleware above and actually does the work
// of validating a request.
func ValidateRequestFromContext(ctx echo.Context, router routers.Router, options *Options) *echo.HTTPError {
	req := ctx.Request()
	route, pathParams, err := router.FindRoute(req)

	// We failed to find a matching route for the request.
	if err != nil {
		if errors.Is(err, routers.ErrMethodNotAllowed) {
			return echo.NewHTTPError(http.StatusMethodNotAllowed)
		}

		switch e := err.(type) {
		case *routers.RouteError:
			// We've got a bad request, the path requested doesn't match
			// either server, or path, or something.
			return echo.NewHTTPError(http.StatusNotFound, e.Reason)
		default:
			// This should never happen today, but if our upstream code changes,
			// we don't want to crash the server, so handle the unexpected error.
			return echo.NewHTTPError(http.StatusInternalServerError,
				fmt.Sprintf("error validating route: %s", err.Error()))
		}
	}

	validationInput := &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: pathParams,
		Route:      route,
	}

	// Pass the Echo context into the request validator, so that any callbacks
	// which it invokes make it available.
	requestContext := context.WithValue(context.Background(), EchoContextKey, ctx) //nolint:staticcheck

	if options != nil {
		validationInput.Options = &options.Options
		validationInput.ParamDecoder = options.ParamDecoder
		requestContext = context.WithValue(requestContext, UserDataKey, options.UserData) //nolint:staticcheck
	}

	err = openapi3filter.ValidateRequest(requestContext, validationInput)
	if err != nil {
		me := openapi3.MultiError{}
		if errors.As(err, &me) {
			errFunc := getMultiErrorHandlerFromOptions(options)
			return errFunc(me)
		}

		switch e := err.(type) {
		case *openapi3filter.RequestError:
			// We've got a bad request
			// Split up the verbose error by lines and return the first one
			// openapi errors seem to be multi-line with a decent message on the first
			errorLines := strings.Split(e.Error(), "\n")
			return &echo.HTTPError{
				Code:     http.StatusBadRequest,
				Message:  errorLines[0],
				Internal: err,
			}
		case *openapi3filter.SecurityRequirementsError:
			for _, err := range e.Errors {
				httpErr, ok := err.(*echo.HTTPError)
				if ok {
					return httpErr
				}
			}
			return &echo.HTTPError{
				Code:     http.StatusForbidden,
				Message:  e.Error(),
				Internal: err,
			}
		default:
			// This should never happen today, but if our upstream code changes,
			// we don't want to crash the server, so handle the unexpected error.
			return &echo.HTTPError{
				Code:     http.StatusInternalServerError,
				Message:  fmt.Sprintf("error validating request: %s", err),
				Internal: err,
			}
		}
	}
	return nil
}

// GetEchoContext gets the echo context from within requests. It returns
// nil if not found or wrong type.
func GetEchoContext(c context.Context) echo.Context {
	iface := c.Value(EchoContextKey)
	if iface == nil {
		return nil
	}
	eCtx, ok := iface.(echo.Context)
	if !ok {
		return nil
	}
	return eCtx
}

func GetUserData(c context.Context) any {
	return c.Value(UserDataKey)
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

// attempt to get the MultiErrorHandler from the options. If it is not set,
// return a default handler
func getMultiErrorHandlerFromOptions(options *Options) MultiErrorHandler {
	if options == nil {
		return defaultMultiErrorHandler
	}

	if options.MultiErrorHandler == nil {
		return defaultMultiErrorHandler
	}

	return options.MultiErrorHandler
}

// defaultMultiErrorHandler returns a StatusBadRequest (400) and a list
// of all of the errors. This method is called if there are no other
// methods defined on the options.
func defaultMultiErrorHandler(me openapi3.MultiError) *echo.HTTPError {
	return &echo.HTTPError{
		Code:     http.StatusBadRequest,
		Message:  me.Error(),
		Internal: me,
	}
}
