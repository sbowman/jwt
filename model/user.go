package model

import "errors"

var (
	// UserDB mimics a database of users.
	UserDB = make(map[string]User)

	// ErrNotFound returned if the username is invalid.
	ErrNotFound = errors.New("user not found")
)

// User represents an authenticated user account.
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Role      string `json:"role"`

	// Password won't be included with JSON response!
	Password string `json:"-"`

	// Issued indicates when the JWT token for this user was issued.
	Issued JWTTime `json:"iat,omitempty"`

	// Expires indicates when the JWT token for this user expires.
	Expires JWTTime `json:"exp,omitempty"`
}

// NewUser generates a new User object.
func NewUser(username, password, email, first, last, role string) User {
	return User{
		Username:  username,
		Password:  password,
		Email:     email,
		FirstName: first,
		LastName:  last,
		Role:      role,
	}
}

// FindUser looks up a user by username.
func FindUser(username string) (User, error) {
	user, ok := UserDB[username]
	if !ok {
		return User{}, ErrNotFound
	}

	return user, nil
}

// Fake a database...
func init() {
	user := NewUser("jdoe", "helloworld", "jdoe@nowhere.com", "John", "Doe", "admin")
	UserDB["jdoe"] = user
}
