package controller

import (
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// prometheusHandlers - handler for Prometheus metrics
func prometheusHandlers(r *mux.Router) {
	// Expose Prometheus metrics at /metrics
	r.Handle("/metrics", promhttp.Handler())
}
