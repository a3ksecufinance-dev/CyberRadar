// Package observe instruments CRP services with Prometheus metrics and
// OpenTelemetry traces from a single HTTP middleware.
//
// Prometheus, Grafana and Jaeger were already deployed but received nothing:
// no service exposed /metrics and none emitted a span, so none of the platform's
// stated targets — 99.99% availability, MTTD under five minutes, API latency
// under 200ms — could be measured at all.
package observe

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// latencyBuckets straddle the platform's 200ms API latency target so the SLO
// can be read straight off the histogram.
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1, 2.5, 5}

var (
	registry = prometheus.NewRegistry()

	requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "crp_http_requests_total",
		Help: "HTTP requests handled, by service, method, route and status class.",
	}, []string{"service", "method", "route", "status"})

	latency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "crp_http_request_duration_seconds",
		Help:    "HTTP request latency, by service, method and route.",
		Buckets: latencyBuckets,
	}, []string{"service", "method", "route"})

	inFlight = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "crp_http_requests_in_flight",
		Help: "HTTP requests currently being served, by service.",
	}, []string{"service"})

	registerOnce sync.Once
)

func register() {
	registerOnce.Do(func() {
		registry.MustRegister(
			requests, latency, inFlight,
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		)
	})
}

// MustRegister adds collectors to the registry that MetricsHandler serves.
//
// The platform deliberately does not use the default Prometheus registry, so a
// metric declared with promauto elsewhere would be collected by nobody. Other
// packages register through here instead, and their metrics land on the same
// /metrics endpoint as the HTTP ones.
func MustRegister(cs ...prometheus.Collector) {
	register()
	registry.MustRegister(cs...)
}

// MetricsHandler serves the platform registry for Prometheus to scrape.
func MetricsHandler() http.Handler {
	register()
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

// Middleware records one Prometheus observation and one OpenTelemetry span per
// request. Mount it before the auth middleware so rejected requests are counted
// too — a spike of 401s is exactly what an operator needs to see.
func Middleware(service string) func(http.Handler) http.Handler {
	register()
	tracer := otel.Tracer("github.com/cyberradar/platform/internal/pkg/observe")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			inFlight.WithLabelValues(service).Inc()
			defer inFlight.WithLabelValues(service).Dec()

			// Continue an incoming trace when one is present, so a request that
			// crosses services stays a single trace.
			ctx := otel.GetTextMapPropagator().Extract(r.Context(),
				propagation.HeaderCarrier(r.Header))
			ctx, span := tracer.Start(ctx, r.Method, trace.WithSpanKind(trace.SpanKindServer))
			defer span.End()

			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r.WithContext(ctx))

			// The chi route pattern, not the raw path: /assets/{id} keeps the
			// label bounded where /assets/<uuid> would grow without limit.
			route := routePattern(r)
			status := ww.Status()
			if status == 0 {
				status = http.StatusOK
			}

			requests.WithLabelValues(service, r.Method, route, strconv.Itoa(status)).Inc()
			latency.WithLabelValues(service, r.Method, route).Observe(time.Since(start).Seconds())

			span.SetName(r.Method + " " + route)
			span.SetAttributes(
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.HTTPRoute(route),
				semconv.HTTPResponseStatusCode(status),
			)
			if status >= http.StatusInternalServerError {
				span.SetStatus(codes.Error, http.StatusText(status))
			}
		})
	}
}

// routePattern returns the matched chi pattern, or "unmatched" when no route
// took the request. Never the raw path: that would make the label unbounded.
//
// The patterns are joined rather than read from RoutePattern(), because this
// middleware is mounted on the root router: there RoutePattern() only reports
// the mount point, so every API call would collapse into a single "/api/v1/*"
// series. RoutePatterns accumulates each nested segment.
func routePattern(r *http.Request) string {
	rc := chi.RouteContext(r.Context())
	if rc == nil || len(rc.RoutePatterns) == 0 {
		return "unmatched"
	}
	pattern := strings.Join(rc.RoutePatterns, "")
	// Mounts leave a wildcard behind at each join: /api/v1/*/tenants/* .
	pattern = strings.ReplaceAll(pattern, "/*/", "/")
	pattern = strings.TrimSuffix(pattern, "/*")
	// An index route contributes a bare "/", so /tenants and /tenants/ would
	// otherwise be two series for the same endpoint.
	if len(pattern) > 1 {
		pattern = strings.TrimSuffix(pattern, "/")
	}
	if pattern == "" {
		return "/"
	}
	return pattern
}

// InitTracing configures the global tracer provider to export over OTLP/gRPC.
//
// An empty endpoint disables tracing and returns a no-op shutdown, so a service
// starts perfectly well without a collector — observability must never be the
// reason a security platform fails to boot.
func InitTracing(ctx context.Context, service, version, endpoint string) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }

	endpoint = strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://")
	if endpoint == "" {
		return noop, nil
	}

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return noop, err
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(service),
		semconv.ServiceVersion(version),
	))
	if err != nil {
		return noop, err
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	return provider.Shutdown, nil
}

// TenantAttribute labels a span with the caller's tenant. Handlers may add it
// once the auth middleware has resolved the identity.
func TenantAttribute(ctx context.Context, tenantID string) {
	trace.SpanFromContext(ctx).SetAttributes(attribute.String("crp.tenant_id", tenantID))
}
