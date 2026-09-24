package response

import (
	"encoding/json"
	"net/http"
)

// Envelope is the standard API response envelope.
type Envelope struct {
	Data  any    `json:"data"`
	Meta  *Meta  `json:"meta,omitempty"`
	Error *Error `json:"error"`
}

// Meta holds pagination and context info.
type Meta struct {
	Page     int    `json:"page,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Total    int64  `json:"total,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// Error represents a structured API error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func write(w http.ResponseWriter, status int, payload Envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// JSON sends a raw JSON response with an arbitrary status code.
// Prefer the typed helpers (OK, Created, BadRequest, etc.) when possible.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// OK sends a 200 response with data.
func OK(w http.ResponseWriter, data any) {
	write(w, http.StatusOK, Envelope{Data: data, Error: nil})
}

// OKWithMeta sends a 200 response with data and pagination meta.
func OKWithMeta(w http.ResponseWriter, data any, meta *Meta) {
	write(w, http.StatusOK, Envelope{Data: data, Meta: meta, Error: nil})
}

// Created sends a 201 response with the created resource.
func Created(w http.ResponseWriter, data any) {
	write(w, http.StatusCreated, Envelope{Data: data, Error: nil})
}

// NoContent sends a 204 response.
func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// BadRequest sends a 400 response.
func BadRequest(w http.ResponseWriter, code, message string, details ...any) {
	var d any
	if len(details) > 0 {
		d = details[0]
	}
	write(w, http.StatusBadRequest, Envelope{Error: &Error{Code: code, Message: message, Details: d}})
}

// Unauthorized sends a 401 response.
func Unauthorized(w http.ResponseWriter, message string) {
	write(w, http.StatusUnauthorized, Envelope{Error: &Error{Code: "UNAUTHORIZED", Message: message}})
}

// Forbidden sends a 403 response.
func Forbidden(w http.ResponseWriter, message string) {
	write(w, http.StatusForbidden, Envelope{Error: &Error{Code: "FORBIDDEN", Message: message}})
}

// NotFound sends a 404 response.
// NotFound answers 404 with message as given.
//
// It used to take a resource name and append " not found" itself, which none
// of the other helpers do. Most callers passed a full message instead — a
// domain error already reading "X not found" — so the answer came out as
// "X not found not found". It now takes a message, like Unauthorized,
// Forbidden and Conflict.
func NotFound(w http.ResponseWriter, message string) {
	write(w, http.StatusNotFound, Envelope{Error: &Error{
		Code:    "NOT_FOUND",
		Message: message,
	}})
}

// Conflict sends a 409 response.
func Conflict(w http.ResponseWriter, message string) {
	write(w, http.StatusConflict, Envelope{Error: &Error{Code: "CONFLICT", Message: message}})
}

// UnprocessableEntity sends a 422 response.
func UnprocessableEntity(w http.ResponseWriter, details any) {
	write(w, http.StatusUnprocessableEntity, Envelope{Error: &Error{
		Code:    "VALIDATION_ERROR",
		Message: "Request validation failed",
		Details: details,
	}})
}

// TooManyRequests sends a 429 response.
func TooManyRequests(w http.ResponseWriter) {
	write(w, http.StatusTooManyRequests, Envelope{Error: &Error{
		Code:    "RATE_LIMIT_EXCEEDED",
		Message: "Too many requests, please try again later",
	}})
}

// InternalError sends a 500 response. Never expose internal error details to the client.
func InternalError(w http.ResponseWriter) {
	write(w, http.StatusInternalServerError, Envelope{Error: &Error{
		Code:    "INTERNAL_ERROR",
		Message: "An internal error occurred",
	}})
}

// ServiceUnavailable sends a 503 response.
func ServiceUnavailable(w http.ResponseWriter) {
	write(w, http.StatusServiceUnavailable, Envelope{Error: &Error{
		Code:    "SERVICE_UNAVAILABLE",
		Message: "Service temporarily unavailable",
	}})
}
