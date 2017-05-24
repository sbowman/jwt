package handler

import (
	"fmt"
	"net/http"
	"os"
)

// Sample is a sample secure API call.  Returns the word "OK" followed by the
// user's name if the user is valid.
//
// Put your token in the "Authorization" header, e.g.
//
//     Authorization: JWT <my token here>
//
func Sample(out http.ResponseWriter, req *http.Request) {
	user, err := IsAuthorized(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid user: %s\n", err)
		unauthorized(out)
		return
	}

	out.Header().Set("Content-Type", "text/plain")
	out.Write([]byte("OK " + user.FirstName + " " + user.LastName))
}
