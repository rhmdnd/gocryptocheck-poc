# Golang Cryptography Report Tooling

Make it easier to detect and document cryptographic usage in a Golang project
by reporting potential cryptographic functions. Reports are produced in
[CycloneDX](https://cyclonedx.org/) format.

This prototype reports code that accesses functions from the
[crypto](https://pkg.go.dev/crypto) and
[golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) modules.

Build the tool:

```console
$ go build -o gocryptocheck main.go
```

Run the tool on a Golang project repository:

```console
$ ../gocryptocheck-poc/gocryptocheck ./...                                                     
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "crypto/sha1.New",
      "description": "Undocumented cryptographic usage. Please add a comment of the form `CRYPTO-USAGE: \u003creason\u003e`.",
      "file": "pkg/utils/nameutils.go",
      "line": 23
    }
  ]
}
```

Add a comment describing the usage:

```diff
$ git d
diff --git a/pkg/utils/nameutils.go b/pkg/utils/nameutils.go
index b4691f44..92cfc2a6 100644
--- a/pkg/utils/nameutils.go
+++ b/pkg/utils/nameutils.go
@@ -17,8 +17,8 @@ func LengthName(maxLen int, hashPrefix string, format string, a ...interface{})


-       // We can suppress the gosec warning about sha1 here because we don't use sha1 for crypto
-       // purposes, but only as a string shortener
+       // CRYPTO-USAGE: SHA1 is only used to hash a given string so it can be safely shortened. It's not being used to protect sensitive data.
+       // Suppress the gosec warning about using SHA1 because we're not using it for cryptographic purposes.
        // #nosec G401
        hasher := sha1.New()
        io.WriteString(hasher, friendlyName)
```

Run the tool again:

```console
$ ../gocryptocheck-poc/gocryptocheck ./...
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "crypto/sha1.New",
      "description": "Documented: CRYPTO-USAGE: SHA1 is only used to hash a given string so it can be safely shortened. It's not being used to protect sensitive data.",
      "file": "pkg/utils/nameutils.go",
      "line": 23
    }
  ]
}
```

This prototype was generated with the help of ChatGPT `o1-mini-high` with the intent of sussing out viability of this approach.
