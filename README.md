# jwks4jwt

`jwks4jwt` creates a [JWK Set](https://tools.ietf.org/html/rfc7517) from a directory of *public* X.509 PEM encoded certificates intended to be used for verifying JWT signatures.

### installation

You can download binaries from the [releases page](https://github.com/brandwatchltd/jwks4jwt/releases)

Or using `go get`

```
go get -u https://github.com/brandwatchltd/jwks4jwt
```

### usage

```
jwks4jwt --certdir ./my-certs > jwks.json
```
