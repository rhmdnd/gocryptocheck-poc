# Golang Cryptography Report Tooling

Make it easier to detect and document cryptographic usage in a Golang project
by reporting potential cryptographic functions. Reports are produced in
[CycloneDX](https://cyclonedx.org/) format by default, but the tool also
supports plain text and [SPDX](https://spdx.dev/).

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
$ ../gocryptocheck-poc/gocryptocheck --excludeDir vendor
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "components": [
    {
      "type": "module",
      "name": "crypto/sha1.New",
      "description": "Undocumented cryptographic usage. Please add a comment of the form `gocryptocheck: \u003crationale\u003e[; key: value...]`.",
      "file": "pkg/utils/nameutils.go",
      "line": 23,
      "properties": {
        "algorithm": "SHA-1",
        "callingFunction": "LengthName",
        "cryptographyType": "Message Digest",
        "moduleVersion": "go1.23.0"
      }
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
$ ../gocryptocheck-poc/gocryptocheck --excludeDir vendor
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "components": [
    {
      "type": "module",
      "name": "crypto/sha1.New",
      "description": "Documented: sha1.New() is only used here to hash a string so it's shorter",
      "file": "pkg/utils/nameutils.go",
      "line": 24,
      "properties": {
        "algorithm": "SHA-1",
        "callingFunction": "LengthName",
        "cryptographyType": "Message Digest",
        "moduleVersion": "go1.23.0"
      }
    }
  ]
}
```

Generate reports in SPDX:

```console
 $ ../gocryptocheck-poc/gocryptocheck -format spdx --excludeDir vendor
SPDXVersion: SPDX-2.2
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: gocryptocheck Cryptographic Usage SPDX Report
DocumentNamespace: http://spdx.org/spdxdocs/gocryptocheck-1745337348
Creator: Tool: gocryptocheck
Created: 2025-04-22T10:55:48-05:00

##### Cryptographic usage found in pkg/utils/nameutils.go at line 24
PackageName: crypto/sha1.New
SPDXID: SPDXRef-crypto.sha1.New-24
PackageVersion: go1.23.0
PackageDownloadLocation: NOASSERTION
PackageDescription: Documented: sha1.New() is only used here to hash a string so it's shorter
PackageComment: algorithm: SHA-1
PackageComment: cryptographyType: Message Digest
PackageComment: callingFunction: LengthName
```

Or plain text:

```console
$ ../gocryptocheck-poc/gocryptocheck -format text --excludeDir vendor
pkg/utils/nameutils.go:24: crypto/sha1.New - Documented: sha1.New() is only used here to hash a string so it's shorter
  Additional details:
    moduleVersion: go1.23.0
    algorithm: SHA-1
    cryptographyType: Message Digest
    callingFunction: LengthName
```

This prototype was generated with the help of ChatGPT `o1-mini-high` with the intent of sussing out viability of this approach.
