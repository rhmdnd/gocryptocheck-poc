# Golang Cryptography Report Tooling

Make it easier to detect and document cryptographic usage in a Golang project
by reporting potential cryptographic functions. Reports are produced in
[CycloneDX](https://cyclonedx.org/) format by default since it has support for cryptographic concepts built into the [schema](https://cyclonedx.org/docs/1.6/json/#components_items_cryptoProperties).

This prototype reports code that accesses functions from the
[crypto](https://pkg.go.dev/crypto) and
[golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) modules.

## Install

Build the tool:

```console
$ go build -o gocryptocheck main.go
```

## Usage

Run the tool on a Golang project repository:

```console
$ ../gocryptocheck-poc/gocryptocheck -format cyclonedx -excludeDir vendor
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "crypto/sha1.New",
      "cryptoProperties": {
        "algorithmProperties": {
          "cryptoFunctions": [
            "digest"
          ],
          "primitive": "hash"
        },
        "assetType": "algorithm"
      },
      "properties": [
        {
          "name": "callingFunction",
          "value": "LengthName"
        },
        {
          "name": "file",
          "value": "pkg/utils/nameutils.go"
        },
        {
          "name": "line",
          "value": 23
        },
        {
          "name": "rationale",
          "value": "Undocumented cryptographic usage. Please add a comment of the form `gocryptocheck: \u003crationale\u003e[; key: value...]`."
        }
      ]
    }
  ]
}
```

Add a comment describing the usage:

```diff
$ git diff
diff --git a/pkg/utils/nameutils.go b/pkg/utils/nameutils.go
index b4691f44a..8c046da46 100644
--- a/pkg/utils/nameutils.go
+++ b/pkg/utils/nameutils.go
@@ -17,6 +17,7 @@ func LengthName(maxLen int, hashPrefix string, format string, a ...interface{})

        // If that's too long, just hash the name. It's not very user friendly, but whatever
        //
+       // gocryptocheck: sha1.New() is only used here to hash a string so it's shorter
        // We can suppress the gosec warning about sha1 here because we don't use sha1 for crypto
        // purposes, but only as a string shortener
        // #nosec G401
```

Run the tool again:

```console
$ ../gocryptocheck-poc/gocryptocheck -format cyclonedx -excludeDir vendor
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "crypto/sha1.New",
      "cryptoProperties": {
        "algorithmProperties": {
          "cryptoFunctions": [
            "digest"
          ],
          "primitive": "hash"
        },
        "assetType": "algorithm"
      },
      "properties": [
        {
          "name": "callingFunction",
          "value": "LengthName"
        },
        {
          "name": "file",
          "value": "pkg/utils/nameutils.go"
        },
        {
          "name": "line",
          "value": 24
        },
        {
          "name": "rationale",
          "value": "sha1.New() is only used here to hash a string so it's shorter"
        }
      ]
    }
  ]
}
```

This prototype was generated with the help of ChatGPT `o1-mini-high` with the intent of sussing out viability of this approach.
