package model

import (
	"errors"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/sbowman/jwt/tokens"
)

var (
	// ErrNoKeyID returned if the JWT lacks a kid value in the header.
	ErrNoKeyID = errors.New("missing key ID in header")

	// ErrNoKey returned if the key ID is invalid (or expired).
	ErrNoKey = errors.New("invalid key ID")

	// ErrInvalidAlgorithm returned if the algorithm is the wrong type.
	ErrInvalidAlgorithm = errors.New("invalid algorithm")

	// ErrTokenExpired returned if the JWT has expired.
	ErrTokenExpired = errors.New("token expired")

	// ErrTokenUsedBeforeIssued returned if the token is used prematurely.
	ErrTokenUsedBeforeIssued = errors.New("token used before issued")
)

// Token generates a JWT token for the user, complete with institution
// information.  Token will expire in one hour.
func (u User) Token() ([]byte, error) {
	issued := time.Now().UTC()
	expires := issued.Add(time.Hour)

	u.Issued = JWTTime{issued}
	u.Expires = JWTTime{expires}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, u)

	key := tokens.CurrentKey
	token.Header["kid"] = key.ID

	str, err := token.SignedString(key.PrivateKey)
	if err != nil {
		return nil, err
	}

	return []byte(str), nil
}

// Valid validates the JWT token expiration based issued time and expiration.
func (u User) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()

	expires := u.Expires.Unix()
	if expires != 0 && now > expires {
		vErr.Inner = ErrTokenExpired
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	issued := u.Issued.Unix()
	if issued != 0 && now < issued {
		vErr.Inner = ErrTokenUsedBeforeIssued
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

// VerifyUser validates and converts a JWT token.
func VerifyUser(token string) (User, error) {
	var user User

	if _, err := jwt.ParseWithClaims(token, &user, DetermineKey); err != nil {
		return user, err
	}

	return user, nil
}

// DetermineKey looks up the public key and confirms the algorithm.
func DetermineKey(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, ErrInvalidAlgorithm
	}

	kid := token.Header["kid"].(string)
	if kid == "" {
		return nil, ErrNoKeyID
	}

	key := tokens.Keys[kid]
	if key == nil {
		return nil, ErrNoKey
	}

	return &key.PublicKey, nil
}

// JWTTime enforces JSON marshaling the time in seconds.
type JWTTime struct {
	time.Time
}

// MarshalJSON marshals the time as a UNIX timestamp in seconds.
func (t JWTTime) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}

	return []byte(strconv.FormatInt(t.Unix(), 10)), nil
}

// UnmarshalJSON unmarshals the data assuming an integer timestamp in seconds.
func (t *JWTTime) UnmarshalJSON(data []byte) error {
	if data == nil || string(data) == "null" {
		return nil
	}

	ts, err := strconv.ParseInt(string(data), 10, 0)
	if err != nil {
		return err
	}

	t.Time = time.Unix(ts, 0)
	return nil
}
