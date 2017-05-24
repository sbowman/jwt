# Working with JSON Web Tokens

This sample project outlines a basic workflow for enabling JSON Web Tokens in 
your application.

For more information on JSON Web Tokens, visit https://jwt.io for more info, 
as well as the IETF spec, 
https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32

## Why JSON Web Tokens (JWT)?

JSON Web Tokens are using in authenticating RESTful and other web-based APIs
(e.g. gRPC).  

Traditionally web applications have been authenticated using a workflow similar
to the following:

* The client submits a username and password to the server.
* The server confirms the user's account information.
* The server generates a token and stores it in a database of user tokens.
* The server returns the token to the client.
* The client submits the token with every subsequent request.
* The server looks up the token in user tokens database to retrieve the user's account information.
* The server confirms the user's authorization information and takes action.

There are several problems with the above scenario.

First, the server is required to keep a database of tokens mapped to user 
accounts.  These tokens have to be kept around for some amount of time, using
up storage space on the server.  If a user's account authenticates from multiple
clients (laptop and tablet, family members in different rooms, etc.), the
server must either allow for multiple copies or return the same key to repeatedly,
causing security issues.

For every request to the server, a separate trip to the database is required to
retrieve and confirm the user's authorization information.  This means multiple
requests to the database, reducing the performance of the system by more half 
its potential right out of the gate.

Alternatively some servers will store the user information in a cache such as 
Redis.  This is more performant than a database request and alleviates the 
additional pressure on the database.  But it simply spreads problems to other
servers.  Caching servers must now be deployed, requiring additional hardware.
There is still a separate network call to the cache.  More importantly, it does 
raise its own set of security issues by spreading authentication and personal 
information around on the system.  And it's easy for the cache and the database
to get "out of sync" with one another.  For example, the cache could fail to
expire a user account that was disabled in the server.

An alternative workflow is supported by JWT:

* The client submits a username and password to the server.
* The server confirms the user's account information.
* The server creates a JSON document containing relevant user information: username, email, role.
* The server creates a signed JSON Web Token using the server's private key.
* The server returns the JWT to the client.
* The client submits the JWT with every subsequent request in the Authorization header.
* The server confirms the JWT signature is valid.
* The server confirms the user's authorization information, e.g. role, and takes action.

Notice that no separate trip to the database is required, no storage of tokens.
Multiple clients may use the system and be expired separately.  

Clients themselves may use the information in the JWT to perform local validation 
before submitting requests.  For example, a JavaScript client may choose not to
display certain menu options to users not in the "admin" role.

On top of this, entire sets of tokens may be invalidated immediately by simply
rotating the server keys.

## JSON Web Token Components

A JWT is broken into three pieces, separated by periods (.):

* the header 
* the payload 
* the signature

The header contains information about how the key was signed (_algo_) and the ID 
of the public key used in the asymmetric signing process (_kid_).  This 
information is used to decrypt the signed token so the client or server may view 
and use the information within.

The payload is the JSON document returned by the server as a Base64-encoded 
string.  It is not encrypted.

The signature is encrypted using the algorithm indicated in the header.  If an
asymmetric signing method such as RSA was used, a key ID may be included in the
header to reference back to a set of public keys published by the server that 
generated the token.  Use that public key to decrypt the signature and confirm
its authenticity.

## Caveat

At the minimum, a JWT is digitally signed.  This allows the server to ensure the
same authorization information it sent to the client is what it got back, i.e.
the JWT cannot be changed without invalidating the signature.

JWT may be signed using a symmetrical signing method such as HMAC.  While this
is supported, I personally recommend using the asymmetrical RSA public/private
key pairs.  With HMAC signatures, the client and the server have a copy of the
key.  This does not allow you to rotate keys without creating a major headache
trying to distribute new keys to clients.

Instead, use the RSA algorithm.  Expose your server's public keys as a JSON 
object (key ID mapped to public key) available as a web request.  The client 
may download a new set of public keys at any time and match them to the key ID
(_kid_) tranmitted in the JWT header.

Furthermore, it is a requirement that you transmit your JSON Web Tokens over
a secure connection, namely **TLS/SSL**.  While signed JWT is guaranteed to be
genuine, hijacking and decryping them them from an insecure connection is quite 
easily done, essentially allowing a hacker to hijack a client's session or
capture personal information (hence why you don't include a password in a JWT).  

## Demo Project

This project contains demonstration code to generate and manage JSON Web Tokens
in a Go application.  The code utilizes the Go JWT package from 
https://github.com/dgrijalva/jwt-go.  

There is a Makefile in the project that handles generating keys and building 
the applications (client, server).  The specific tasks will be referenced below.

The following examples were written for macOS, but should work unaltered on 
Linux.  Windows users will have to translate.

### Step 1: Create Server Keys

Typically I like to use Cobra (https://github.com/spf13/cobra) to build up 
additional functionality in my server applications.  It allows additional 
commands to be run using your server binary in addition to launching the REST
server.

In the `cmd/generate_key.go` package, we have the code to generate a new key pair
in the `./keys` directory.  The server will use these keys to sign the JSON Web
Token, as well as publish the public keys for clients to consume and use to 
decrypt the token.

Here's a quick walk through of the relevant parts.  See `cmd/generate_key.go`
for the complete code.

First, use the Go RSA package to generate a 2048-bit public/private key:

    pk, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Unable to generate RSA keys: %s\n", err)
        os.Exit(1)
    }

Create a directory to store the keys in, if it doesn't already exist:

    directory := viper.GetString("jwt.keys")

    if err = os.MkdirAll(directory, 0700); err != nil {
        fmt.Fprintf(os.Stderr, "Unable to create directory %s: %s\n", directory, err)
        os.Exit(1)
    }

We need a unique identifier for the keys.  This will be included in the JWT
header as the key ID, i.e. _kid_.  It will also be published in a JSON object 
map pointing to the public key clients may use to decrypt the token.  Note that
I'm using UUID version 1 provided by the `github.com/satori/go.uuid` package, so 
the tokens are timestamped; this makes it easier to expire old IDs (if you're 
worried about exposing your MAC address, run from a container or VM with a 
random MAC address):

    // We need these to be ordered...
    id := uuid.NewV1().String()

Export the keys as X509 certificates, so we can write them to disk.  We'll use
the key ID as the filename: 

    der := x509.MarshalPKCS1PrivateKey(pk)
    file := filepath.Join(directory, id+".key")
    if err = ioutil.WriteFile(file, der, 0600); err != nil {
        fmt.Fprintf(os.Stderr, "Unable to save key to %s: %s\n", file, err)
        os.Exit(1)
    }

### Step 2: Setup a Web Server and Expose the Public Keys

We'll take the very basic step of exposing the public keys to clients in a web
server.  

First, lets load the keys from disk and cache them in memory.  We'll use the
Go `filepath` package to walk the `./keys` directory and on each file load the
key, transforming it from an X509 to an Go RSA key internal representation.  See
`tokens/keys.go` for the details, but here's where we load and parse an 
individual key file:

    func loadKey(path string, info os.FileInfo, err error) error {
        if info.IsDir() {
            return err
        }

        if filepath.Ext(path) == ".key" {
            id := filepath.Base(path)
            id = id[:len(id)-4]

            der, err := ioutil.ReadFile(path)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Unable to read key file %s: %s", path, err)
                return nil
            }

            cert, err := x509.ParsePKCS1PrivateKey(der)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Unable to parse RSA key in %s: %s", path, err)
                return nil
            }

            Keys[id] = cert
        }

        return nil
    }

Note the above only loads files with the `.key` extension.  Recall we wrote the
keys to disk using their key ID as the filename.  We cache them in the global 
variable `Keys`, by their base filename, or rather, their key ID.

It should also be noted that we're loading the keys at startup and caching them
in memory.  In a production server, you may want to have your app watch the 
keys directory and refresh the cache when new key files appear.  As it stands,
when we generate a new key we must restart the server.

Alternatively you could store the keys in a database or cache so they're 
available across a server cluster.  That's additional work beyond the scope of
this tutorial.

In our `cmd/root.go` file, we create a web server:

    // Setup an HTTP server
    listen := viper.GetString("http.listen")
    fmt.Printf("Listening for incoming HTTP connections on %s", listen)

    router := handler.Routes()

    if err := http.ListenAndServe(listen, router); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to start server: %s", err)
        os.Exit(1)
    }

The routes are configured in the `Routes()` function in `handler/routes.go`,
using the Gorilla `mux` package (feel free to use whatever Go router you like):

    // Routes configures a handler to route HTTP requests.  Supports only a
    // few endpoints such as the /v1/ping health check and /v1/keys to expose the
    // public keys used to encrypt JSON web tokens.
    func Routes() http.Handler {
        router := mux.NewRouter()

        // Everything is under a /v1 path...
        v1 := router.PathPrefix("/v1").Subrouter()

        // For load balancers, monitors, etc.
        v1.HandleFunc("/ping", Ping).Methods("GET")

        // Retrieve the public keys
        v1.HandleFunc("/keys", PublicKeys).Methods("GET")

        // Allow browsers to access the API
        c := cors.New(cors.Options{
            AllowedOrigins:   []string{"*"},
            AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
            AllowedHeaders:   []string{"*"},
            AllowCredentials: true,
        })

        return c.Handler(router)
    }

The router sets up two routes for our API:

* `/ping` - a simple tool we can use to make sure the server is running
* `/keys` - returns a JSON object mapping the key IDs to valid public keys

Additionally we permit completely open access to our API from JavaScript clients
on web browers using the `github.com/rs/cors` package.  Adjust as your security
needs require.

In the `cmd/root.go` file you'll notice I load the server keys at startup and
cache them in the package `tokens`, under the global variable `Keys`.  The 
"keys" handler peels the public key portion out of the tokens and returns the 
them to the client:

    // PublicKeys returns a map of key ID to public keys available on this server
    // for confirming JWT tokens.
    func PublicKeys(out http.ResponseWriter, req *http.Request) {
        keys := make(map[string]string)

        for id, key := range tokens.Keys {
            pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
            if err != nil {
                fmt.Println(err.Error())
                continue
            }

            block := &pem.Block{
                Type:  "RSA PUBLIC KEY",
                Bytes: pub,
            }
            keys[id] = string(pem.EncodeToMemory(block))
        }

        ok(out, keys)
    }

For additional performance, it may behoove you to write the public keys to 
disk as a `.json` file and serve that up to clients.

You can build the server using the Makefile.  You'll need to build the server
and generate at least one RSA key pair, then you can start the server:

    $ make

    $ make jwt.key
    ./jwt generate key
    Key written to keys/c0cdacf5-40ae-11e7-92f2-a0999b113d59.key
    
    $ make run
    ./jwt 
    Loaded RSA keys: c0cdacf5-40ae-11e7-92f2-a0999b113d59
    Current key ID used for signing JWT: c0cdacf5-40ae-11e7-92f2-a0999b113d59
    Listening for incoming HTTP connections on :9800

Use `curl` to request the keys:

    $ curl 'http://localhost:9800/v1/keys?pretty=t'
    {
        "c0cdacf5-40ae-11e7-92f2-a0999b113d59": "-----BEGIN RSA PUBLIC KEY-----\n
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArv6mvHzCQkQNPHRg69Ma\nHK+LuH
        cai0s2KfRRWodWPPDzxHsROAbQMG3k1hoRoYKW4bller2atd+846cEKSN1\nNDzTRHsIk5HV
        Ixd1aOJS2kW4MEuXaJLsuqsdBLMHjlO2le4WCH5QHzqut4++5PBz\n4os+AwdDSwvPopSiAC
        89oG9WnShYnDs1s5F4ujng7ufKdd9Sx9nGPNqWkcvDl7TJ\nhAUrRbGyi0jy1Hpa74yBSm2V
        tfEX4tfRsvTRTdXWP5PXXozXrKFFVhfnV8siSSGM\n11NpTzqbQYqPUF9ggJ4XCgyJCGpbwP
        fNCQIzRDqP+vvE1EJXJvMprgoLzFWEYuur\nqwIDAQAB\n-----END RSA PUBLIC KEY---
        --\n"
    }

### Step 3: Authenticating a User and Generating a JWT

Let's add an authentication handler to our routes.  Setting up a database and
all that fun stuff is a bit outside the scope of this tutorial, so we'll just
create a simple cache.  

We setup our user and cache in `model/user.go`.  Note that the password is 
blocked from being included in the JSON.  In a real production server you may
not even want to load the password into memory, but rather validate it during
lookup in the database:

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

We've included the `Issued` and `Expires` properties.  These will be included
every time a JWT is generated and returned inside the encrypted token.  Do not
save this information to the database!

Let's generate a token with a one hour expiration time.  It's up to the client
to refresh the token when it nears its expiration:

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

Recall we use the `tokens.CurrentKey` to sign the JWT with our server's private
key.  The client will use our published public key, identified by the _kid_ in
the header, to decrypt the JWT token.

This makes our authentication handler (`handler/auth.go`) relatively simple:

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

For security reasons, you should only ever return a `401 Unauthorized` response.
Don't tell unknown clients what users exist on the system by returning "user not
found", or that a password was bad by returning "invalid password".  Let them
guess at what's wrong.

In that last section there, we call for the user to generate his token and we
return that in the body of the response.

You can try this out using `curl`:

    $ curl -v -XPOST 'http://localhost:9800/v1/auth?u=jdoe&p=helloworld'
    *   Trying ::1...
    * Connected to localhost (::1) port 9800 (#0)
    > POST /v1/auth?u=jdoe&p=helloworld HTTP/1.1
    > Host: localhost:9800
    > User-Agent: curl/7.43.0
    > Accept: */*
    > 
    < HTTP/1.1 200 OK
    < Content-Type: application/jwt
    < Vary: Origin
    < Date: Wed, 24 May 2017 19:27:02 GMT
    < Content-Length: 628
    < 
    * Connection #0 to host localhost left intact
    eyJhbGciOiJSUzI1NiIsImtpZCI6ImMwY2RhY2Y1LTQwYWUtMTFlNy05MmYyLWEwOTk5YjExM2Q1
    OSIsInR5cCI6IkpXVCJ9.eyJpZCI6IiIsInVzZXJuYW1lIjoiamRvZSIsImVtYWlsIjoiamRvZU
    Bub3doZXJlLmNvbSIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIiwicm9sZS
    I6ImFkbWluIiwiaWF0IjoxNDk1NjU0MDIyLCJleHAiOjE0OTU2NTc2MjJ9.izgOhoLE3smP1jsq
    9UL5_FknUU5d4fa5D9YgPAyIE1XZf9sJTNvgCqwfnNJPoqCzjbIzNivDLpCfocIf5hy1vxKcawxr
    MqWfn2rTfkcZzgcpG0cVNXFobXRO5bE1TdUDMxw42PFgm68FZOdWKxj6cdN_BJ48YCVkYMBICORd
    yAizj6wzqAUlIxDQouvGxF1QfaVOQVA4oWc6FcbX8_aZ5DShfVDfmlnG45xRIXFOXNS-Soxfzwfy
    tOD59gR0v2X2h4WbjRnK40JIhyLw-60yOe0fYuYitQi3URmS2yXzI0rt6YByzkd_exdGGmp4Qm91
    fkwxr-d_b57ju9cRy-Gf9Q

Obviously your token will look different from mine, but you get the point.

For fun, you can try to use an invalid user or password:

    curl -v -XPOST 'http://localhost:9800/v1/auth?u=jdoe&p=glorp'
    *   Trying ::1...
    * Connected to localhost (::1) port 9800 (#0)
    > POST /v1/auth?u=jdoe&p=glorp HTTP/1.1
    > Host: localhost:9800
    > User-Agent: curl/7.43.0
    > Accept: */*
    > 
    < HTTP/1.1 401 Unauthorized
    < Vary: Origin
    < Date: Wed, 24 May 2017 19:29:05 GMT
    < Content-Length: 0
    < Content-Type: text/plain; charset=utf-8
    < 
    * Connection #0 to host localhost left intact

Now we need a client to use this token.

### Step 4: Submitting the JWT for Authorization

Any handler/route in our API that requires authorization should watch for the 
`Authorization: JWT <token>` header and use that information to authorize the
user account.  Here's a function we can use to do that:

    // IsAuthorized pulls the token from the Authorization header and validates.
    // Returns the user if valid (good signature, not expired), or an error if 
    // not.
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

Note that at no time in the `IsAuthorized` function do we call the database.  We
don't have to request a user based on some "token to user" map or database table
or cache.  We know the token is signed, that signature is valid, and that we
created it and can trust the information within.

Call this function at the start of any "secure" route and it will return either 
the valid user or an error if the token is invalid or missing.  For example, see
`handler/sample.go`:

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

If `IsAuthorized` returns an error, reject the request.  Otherwise you can 
rely on the fact that the user information in the token is correct and valid,
at least within the time since it was generated.

Let's try it out:

    $ KEY=`curl -XPOST 'http://localhost:9800/v1/auth?u=jdoe&p=helloworld'`
    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
    100   628  100   628    0     0  70506      0 --:--:-- --:--:-- --:--:-- 78500

    $ echo $KEY
    eyJhbGciOiJSUzI1NiIsImtpZCI6ImMwY2RhY2Y1LTQwYWUtMTFlNy05MmYyLWEwOTk5YjExM2Q
    1OSIsInR5cCI6IkpXVCJ9.eyJpZCI6IiIsInVzZXJuYW1lIjoiamRvZSIsImVtYWlsIjoiamRvZU
    Bub3doZXJlLmNvbSIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIiwicm9sZS
    I6ImFkbWluIiwiaWF0IjoxNDk1NjU2MzU0LCJleHAiOjE0OTU2NTk5NTR9.YYtMRaAjGiRq78j3W
    9qOAByPCN4J5_Nzxal-67_--vaCB4D_oQc7c-xXELe1-AsupL52Ld6H31aoHx2gxKG6txqGILN9w
    n_2eOJuprt27PhcE53hq_W0qZFRPTJVQLeXBU1luE8ZV8VrG4Nhkzrz9kzvdKXwPLj2uxtVf23Ln
    pHB0XSOf7CzQwVNMhnLFX_BhtPDe7TzeNlsSGDhxSbY6vNa3mhfI9yRR2iJQKpfa4_LDFWWU1uSk
    APxIWy4B4UxpX8ge2lClCFUKEJxLShwhud_T1x7fwmOUndQW1AYZFH6glVFT4wo9V0WbzC137-qT
    SECxCc_CcV915vb6BCk1w

    $ curl http://localhost:9800/v1/sample -H "Authorization: JWT $KEY"
    OK John Doe

You can try it with a fake token (or wait an hour for your token to expire):

    $ curl -v http://localhost:9800/v1/sample -H "Authorization: JWT whoami"
    *   Trying ::1...
    * Connected to localhost (::1) port 9800 (#0)
    > GET /v1/sample HTTP/1.1
    > Host: localhost:9800
    > User-Agent: curl/7.43.0
    > Accept: */*
    > Authorization: JWT whoami
    > 
    < HTTP/1.1 401 Unauthorized
    < Vary: Origin
    < Date: Wed, 24 May 2017 20:12:43 GMT
    < Content-Length: 0
    < Content-Type: text/plain; charset=utf-8
    < 
    * Connection #0 to host localhost left intact
    
### Step 5: Using the JWT on the Client

Typically we're going to use the JSON Web Token from a web client, such as a 
JavaScript app.  Here's an example of how to use the token once you've 
authenticated:

    function getSample (token) {
        let headers = new Headers({
            'Authorization': 'JWT ' + token
        })

        return new Promise((resolve, reject) => {
            fetch('http://localhost:9800/v1/sample', { headers }).then( response => {
                if (response.ok) {
                    resolve(response.text())
                    return
                }

                reject(response.text())
            })
        })
    }

If you're using a valid token, the response should resolve with "OK John Doe" 
like the previous step.

### Step 6: Updating the JWT

JSON Web Tokens are designed to expire with regularity.  Some services expire
the token in minutes, others hours, some days or even months (not recommended).
Our application expires the token every hour.

When the client notices the token is about to expire, it should request a new
token.  The `PUT /auth` endpoint handles this request.  Simply call that endpoint
without any parameters but using a valid JWT, and our server will return a newly
minted token with an additional hour of expiration time.

Here's the update code, though it looks nearly identical to the original login
code:

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

First we check the authorization like we've done previously.  If the existing
token has already expired, the client is out of luck and must authenticate 
again using username/password.

Then we confirm with the "database" that the user still exists and is valid.
Using the information from the database, we generate a new token and return it,
just as if the user were authentication by username/password for the first time.

## Securing the Tokens

As I mentioned previously, JSON Web Tokens are subject to hijacking.  While the
information contained is guaranteed to be accurate and correct, at least at the
time the token was created, it may be surreptitiously acquired by a third-party
and used to authenticate with the service.

To solve this, **only transmit tokens over TLS/SSL secure communications**.  The
simple solution is to put your application behind an SSL proxy such as Nginx, 
http://nginx.org.  While you can server TLS certificates from your Go app
directly, it can be a pain to setup.  And if you're using a recognized certificate
authority such as Comodo or Verisign, they'll have instructions to help you get
setup using Nginx. 

Some may suggest encrypting the payload.  This is not recommended.  JWT is about
authenticating and authorizing the user.  Securing the payload should be handled
by the SSL layer.  Otherwise your client is now doing the work of decrypting
payloads, instead of just using what's built into the browser already (SSL).

## License

This tutorial and the associated code is licensed under the Apache licence.  See 
LICENSE for more info.

## Support

This tutorial and software is offered as-is.  While I have endeavored to make
this information accurate and current, I make no guarantees that the code is 
100% secure or bug-free.
