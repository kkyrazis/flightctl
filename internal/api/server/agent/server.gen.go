// Package server provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.3.0 DO NOT EDIT.
package server

import (
	"fmt"
	"net/http"

	. "github.com/flightctl/flightctl/api/v1alpha1"
	"github.com/go-chi/chi/v5"
	"github.com/oapi-codegen/runtime"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {

	// (POST /api/v1/certificatesigningrequests)
	CreateCertificateSigningRequest(w http.ResponseWriter, r *http.Request)

	// (GET /api/v1/certificatesigningrequests/{name})
	GetCertificateSigningRequest(w http.ResponseWriter, r *http.Request, name string)

	// (GET /api/v1/devices/{name}/rendered)
	GetRenderedDevice(w http.ResponseWriter, r *http.Request, name string, params GetRenderedDeviceParams)

	// (PATCH /api/v1/devices/{name}/status)
	PatchDeviceStatus(w http.ResponseWriter, r *http.Request, name string)

	// (PUT /api/v1/devices/{name}/status)
	ReplaceDeviceStatus(w http.ResponseWriter, r *http.Request, name string)

	// (POST /api/v1/enrollmentrequests)
	CreateEnrollmentRequest(w http.ResponseWriter, r *http.Request)

	// (GET /api/v1/enrollmentrequests/{name})
	GetEnrollmentRequest(w http.ResponseWriter, r *http.Request, name string)
}

// Unimplemented server implementation that returns http.StatusNotImplemented for each endpoint.

type Unimplemented struct{}

// (POST /api/v1/certificatesigningrequests)
func (_ Unimplemented) CreateCertificateSigningRequest(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

// (GET /api/v1/certificatesigningrequests/{name})
func (_ Unimplemented) GetCertificateSigningRequest(w http.ResponseWriter, r *http.Request, name string) {
	w.WriteHeader(http.StatusNotImplemented)
}

// (GET /api/v1/devices/{name}/rendered)
func (_ Unimplemented) GetRenderedDevice(w http.ResponseWriter, r *http.Request, name string, params GetRenderedDeviceParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

// (PATCH /api/v1/devices/{name}/status)
func (_ Unimplemented) PatchDeviceStatus(w http.ResponseWriter, r *http.Request, name string) {
	w.WriteHeader(http.StatusNotImplemented)
}

// (PUT /api/v1/devices/{name}/status)
func (_ Unimplemented) ReplaceDeviceStatus(w http.ResponseWriter, r *http.Request, name string) {
	w.WriteHeader(http.StatusNotImplemented)
}

// (POST /api/v1/enrollmentrequests)
func (_ Unimplemented) CreateEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

// (GET /api/v1/enrollmentrequests/{name})
func (_ Unimplemented) GetEnrollmentRequest(w http.ResponseWriter, r *http.Request, name string) {
	w.WriteHeader(http.StatusNotImplemented)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler            ServerInterface
	HandlerMiddlewares []MiddlewareFunc
	ErrorHandlerFunc   func(w http.ResponseWriter, r *http.Request, err error)
}

type MiddlewareFunc func(http.Handler) http.Handler

// CreateCertificateSigningRequest operation middleware
func (siw *ServerInterfaceWrapper) CreateCertificateSigningRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.CreateCertificateSigningRequest(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetCertificateSigningRequest operation middleware
func (siw *ServerInterfaceWrapper) GetCertificateSigningRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "name" -------------
	var name string

	err = runtime.BindStyledParameterWithOptions("simple", "name", chi.URLParam(r, "name"), &name, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "name", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetCertificateSigningRequest(w, r, name)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetRenderedDevice operation middleware
func (siw *ServerInterfaceWrapper) GetRenderedDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "name" -------------
	var name string

	err = runtime.BindStyledParameterWithOptions("simple", "name", chi.URLParam(r, "name"), &name, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "name", Err: err})
		return
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params GetRenderedDeviceParams

	// ------------- Optional query parameter "knownRenderedVersion" -------------

	err = runtime.BindQueryParameter("form", true, false, "knownRenderedVersion", r.URL.Query(), &params.KnownRenderedVersion)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "knownRenderedVersion", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetRenderedDevice(w, r, name, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// PatchDeviceStatus operation middleware
func (siw *ServerInterfaceWrapper) PatchDeviceStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "name" -------------
	var name string

	err = runtime.BindStyledParameterWithOptions("simple", "name", chi.URLParam(r, "name"), &name, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "name", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.PatchDeviceStatus(w, r, name)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// ReplaceDeviceStatus operation middleware
func (siw *ServerInterfaceWrapper) ReplaceDeviceStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "name" -------------
	var name string

	err = runtime.BindStyledParameterWithOptions("simple", "name", chi.URLParam(r, "name"), &name, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "name", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.ReplaceDeviceStatus(w, r, name)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// CreateEnrollmentRequest operation middleware
func (siw *ServerInterfaceWrapper) CreateEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.CreateEnrollmentRequest(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetEnrollmentRequest operation middleware
func (siw *ServerInterfaceWrapper) GetEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "name" -------------
	var name string

	err = runtime.BindStyledParameterWithOptions("simple", "name", chi.URLParam(r, "name"), &name, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "name", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetEnrollmentRequest(w, r, name)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

type UnescapedCookieParamError struct {
	ParamName string
	Err       error
}

func (e *UnescapedCookieParamError) Error() string {
	return fmt.Sprintf("error unescaping cookie parameter '%s'", e.ParamName)
}

func (e *UnescapedCookieParamError) Unwrap() error {
	return e.Err
}

type UnmarshalingParamError struct {
	ParamName string
	Err       error
}

func (e *UnmarshalingParamError) Error() string {
	return fmt.Sprintf("Error unmarshaling parameter %s as JSON: %s", e.ParamName, e.Err.Error())
}

func (e *UnmarshalingParamError) Unwrap() error {
	return e.Err
}

type RequiredParamError struct {
	ParamName string
}

func (e *RequiredParamError) Error() string {
	return fmt.Sprintf("Query argument %s is required, but not found", e.ParamName)
}

type RequiredHeaderError struct {
	ParamName string
	Err       error
}

func (e *RequiredHeaderError) Error() string {
	return fmt.Sprintf("Header parameter %s is required, but not found", e.ParamName)
}

func (e *RequiredHeaderError) Unwrap() error {
	return e.Err
}

type InvalidParamFormatError struct {
	ParamName string
	Err       error
}

func (e *InvalidParamFormatError) Error() string {
	return fmt.Sprintf("Invalid format for parameter %s: %s", e.ParamName, e.Err.Error())
}

func (e *InvalidParamFormatError) Unwrap() error {
	return e.Err
}

type TooManyValuesForParamError struct {
	ParamName string
	Count     int
}

func (e *TooManyValuesForParamError) Error() string {
	return fmt.Sprintf("Expected one value for %s, got %d", e.ParamName, e.Count)
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{})
}

type ChiServerOptions struct {
	BaseURL          string
	BaseRouter       chi.Router
	Middlewares      []MiddlewareFunc
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseRouter: r,
	})
}

func HandlerFromMuxWithBaseURL(si ServerInterface, r chi.Router, baseURL string) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseURL:    baseURL,
		BaseRouter: r,
	})
}

// HandlerWithOptions creates http.Handler with additional options
func HandlerWithOptions(si ServerInterface, options ChiServerOptions) http.Handler {
	r := options.BaseRouter

	if r == nil {
		r = chi.NewRouter()
	}
	if options.ErrorHandlerFunc == nil {
		options.ErrorHandlerFunc = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
	wrapper := ServerInterfaceWrapper{
		Handler:            si,
		HandlerMiddlewares: options.Middlewares,
		ErrorHandlerFunc:   options.ErrorHandlerFunc,
	}

	r.Group(func(r chi.Router) {
		r.Post(options.BaseURL+"/api/v1/certificatesigningrequests", wrapper.CreateCertificateSigningRequest)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/api/v1/certificatesigningrequests/{name}", wrapper.GetCertificateSigningRequest)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/api/v1/devices/{name}/rendered", wrapper.GetRenderedDevice)
	})
	r.Group(func(r chi.Router) {
		r.Patch(options.BaseURL+"/api/v1/devices/{name}/status", wrapper.PatchDeviceStatus)
	})
	r.Group(func(r chi.Router) {
		r.Put(options.BaseURL+"/api/v1/devices/{name}/status", wrapper.ReplaceDeviceStatus)
	})
	r.Group(func(r chi.Router) {
		r.Post(options.BaseURL+"/api/v1/enrollmentrequests", wrapper.CreateEnrollmentRequest)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/api/v1/enrollmentrequests/{name}", wrapper.GetEnrollmentRequest)
	})

	return r
}
