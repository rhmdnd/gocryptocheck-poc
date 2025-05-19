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
$ ../gocryptocheck-poc/gocryptocheck -excludeDir vendor
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

Save CBOM output to a file:

```console
$ ../gocryptocheck --excludeDir vendor > cbom.json
```

Use output to find specific cryptographic usage:

```console
$ cat cbom.json| jq '.components[] | select(.name=="crypto/sha256.New")'                                                                                                                                                                                                                                                                                                                                                                              3 ↵
{
  "type": "cryptographic-asset",
  "name": "crypto/sha256.New",
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
      "name": "pkg/asset/agent/image/cache.go:168",
      "value": "gocryptocheck: Used to produce a checksum and validate cached files.\nWrap the reader in TeeReader to calculate sha256 checksum on the fly"
    }
  ]
}
{
  "type": "cryptographic-asset",
  "name": "crypto/sha256.New",
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
      "name": "pkg/asset/agent/image/oc.go:252",
      "value": "gocryptocheck: Used to validate cached installer files and inform the user if the installer is outdated."
    }
  ]
}
{
  "type": "cryptographic-asset",
  "name": "crypto/sha256.New",
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
      "name": "pkg/tfvars/internal/cache/cache.go:145",
      "value": "gocryptocheck: Used to hash files on disk for cache logic.\nWrap the reader in TeeReader to calculate sha256 checksum on the fly"
    }
  ]
}
{
  "type": "cryptographic-asset",
  "name": "crypto/sha256.New",
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
      "name": "terraform/providers/vsphereprivate/resource_vsphereprivate_import_ova.go:346",
      "value": "gocryptocheck: Used to hash the contents of corrupt .ovf files. The hash is used in error messages.\nGet a sha256 on the corrupt OVA file\nand the size of the file"
    }
  ]
}
```

In this case, finding usage of SHA1:

```console
$ cat cbom.json| jq '.components[] | select(.name=="crypto/sha1.Sum")'
{
  "type": "cryptographic-asset",
  "name": "crypto/sha1.Sum",
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
      "name": "pkg/asset/tls/tls.go:152",
      "value": "gocryptocheck: Used to generate a hash of an SSH public key."
    }
  ]
}
```

This prototype was generated with the help of ChatGPT `o1-mini-high` with the intent of sussing out viability of this approach.
