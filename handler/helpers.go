package handler

// Return a JSON document, status 200.
import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func ok(out http.ResponseWriter, req *http.Request, obj interface{}) {
	var doc []byte
	var err error

	if req.URL.Query().Get("pretty") == "t" {
		doc, err = json.MarshalIndent(obj, "", "  ")
	} else {
		doc, err = json.Marshal(obj)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshal controller response object: %s\n", err)
		internalservererror(out, err)
	}

	if _, err := out.Write(doc); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// Return a 204 No Content.
func nocontent(out http.ResponseWriter) {
	out.WriteHeader(http.StatusNoContent)
}

// Send a simple HTTP response.
func send(status int, out http.ResponseWriter, format string, args ...interface{}) {
	out.WriteHeader(status)

	if len(args) == 0 {
		fmt.Fprintf(out, format)
		return
	}

	fmt.Fprintf(out, format, args...)
}

// Return a 400 Bad Request.
func badrequest(out http.ResponseWriter, format string, args ...interface{}) {
	send(http.StatusBadRequest, out, format, args...)
}

// Returns a 404 Not Found.
func notfound(out http.ResponseWriter, format string, args ...interface{}) {
	send(http.StatusNotFound, out, format, args...)
}

// Return a 401 Unauthorized.
func unauthorized(out http.ResponseWriter) {
	out.WriteHeader(http.StatusUnauthorized)
}

// Return a 500 Internal Server Error.
func internalservererror(out http.ResponseWriter, err error) {
	out.WriteHeader(http.StatusInternalServerError)
	out.Write([]byte(err.Error()))
}
