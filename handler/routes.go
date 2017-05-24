package handler

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

// Routes configures a handler to route HTTP requests.  Coeus supports only a
// few endpoints such as the /v1/ping health check and /v1/keys to expose the
// public keys used to encrypt JSON web tokens.
func Routes() http.Handler {
	router := mux.NewRouter()

	// Everything is under a /v1 path...
	v1 := router.PathPrefix("/v1").Subrouter()

	// For load balancers, monitors, etc.
	v1.HandleFunc("/ping", Ping).Methods("GET")

	// Retrieve the JWT public keys
	v1.HandleFunc("/keys", PublicKeys).Methods("GET")

	// Authenticate the user and return a JWT
	v1.HandleFunc("/auth", Authenticate).Methods("POST")

	// Update a token
	v1.HandleFunc("/auth", UpdateToken).Methods("PUT")

	// Our "API"...
	v1.HandleFunc("/sample", Sample).Methods("GET")

	// Allow browsers to access the API
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	return c.Handler(router)
}

// Ping is used to check that Engaged is active, typically by a load balancer.
func Ping(out http.ResponseWriter, req *http.Request) {
	nocontent(out)
}
