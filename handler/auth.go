package handler

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/sbowman/jwt/model"
)

var (
	// ErrInvalidHeader returned from IsAuthorized if the Authorization
	// header is missing or doesn't prefix the token with "JWT" as the
	// authorization type.
	ErrInvalidHeader = errors.New("invalid authorization header")
)

// Authenticate the user and return a JSON Web Token.
func Authenticate(out http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("u")
	password := req.URL.Query().Get("p")

	// Look in our fake database for our user
	user, err := model.FindUser(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid user, %s: %s\n", username, err)
		unauthorized(out)
		return
	}

	if user.Password != password {
		fmt.Fprintf(os.Stderr, "Invalid password for %s: %s\n", username, err)
		unauthorized(out)
		return
	}

	// Generate a JSON Web Token
	token, err := user.Token()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate JWT: %s\n", err)
		unauthorized(out)
		return
	}

	// MIME type, according to
	// https://tools.ietf.org/html/draft-jones-json-web-token-10#page-14
	out.Header().Set("Content-Type", "application/jwt")
	out.Write(token)
}

// UpdateToken generates a new JSON Web Token with the expiration extended.
func UpdateToken(out http.ResponseWriter, req *http.Request) {
	user, err := IsAuthorized(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid user token: %s\n", err)
		unauthorized(out)
		return
	}

	// Confirm the user is still active...
	updating, err := model.FindUser(user.Username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid user, %s: %s\n", user.Username, err)
		unauthorized(out)
		return
	}

	// Generate a JSON Web Token
	token, err := updating.Token()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate JWT: %s\n", err)
		unauthorized(out)
		return
	}

	// MIME type, according to
	// https://tools.ietf.org/html/draft-jones-json-web-token-10#page-14
	out.Header().Set("Content-Type", "application/jwt")
	out.Write(token)
}

// IsAuthorized pulls the token from the Authorization header and validates.
// Returns the user if valid (good signature, not expired), or an error if not.
func IsAuthorized(req *http.Request) (model.User, error) {
	authorization := req.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "JWT ") {
		return model.User{}, ErrInvalidHeader
	}

	pair := strings.Split(authorization, " ")
	if len(pair) < 2 {
		return model.User{}, ErrInvalidHeader
	}

	token := pair[1]
	user, err := model.VerifyUser(token)
	if err != nil {
		return model.User{}, err
	}

	return user, nil
}
