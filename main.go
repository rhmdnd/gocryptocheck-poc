// main.go
package main

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/singlechecker"
)

// cryptoPackages lists known cryptographic package identifiers.
// Any package path that is exactly equal to an entry or starts with entry + "/" is considered cryptographic.
var cryptoPackages = []string{
	"crypto/aes",
	"crypto/cipher",
	"crypto/des",
	"crypto/dsa",
	"crypto/ecdsa",
	"crypto/ed25519",
	"crypto/hmac",
	"crypto/md5",
	"crypto/rand",
	"crypto/rsa",
	"crypto/sha1",
	"crypto/sha256",
	"crypto/sha512",
	"crypto/subtle",
	"golang.org/x/crypto", // This entry covers all packages under golang.org/x/crypto.
}

// isCryptoPackage returns true if pkgPath is a known crypto package or is a subpackage of one.
func isCryptoPackage(pkgPath string) bool {
	for _, cp := range cryptoPackages {
		if pkgPath == cp || strings.HasPrefix(pkgPath, cp+"/") {
			return true
		}
	}
	return false
}

// Analyzer defines the gocryptocheck analyzer.
var Analyzer = &analysis.Analyzer{
	Name: "gocryptocheck",
	Doc:  "reports cryptographic usage that lacks proper CRYPTO-USAGE comments",
	Run:  run,
}

// run is the entry point of the analyzer.
func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		// Traverse the AST of the file.
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// Try to determine the function being called.
			var funObj types.Object
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				funObj = pass.TypesInfo.ObjectOf(fun.Sel)
			case *ast.Ident:
				funObj = pass.TypesInfo.ObjectOf(fun)
			default:
				return true
			}
			if funObj == nil {
				return true
			}
			pkg := funObj.Pkg()
			if pkg == nil {
				return true
			}
			// Check if the function belongs to one of our known cryptographic packages.
			if !isCryptoPackage(pkg.Path()) {
				return true
			}

			// Capture module and function name.
			cryptoModule := pkg.Path()
			cryptoFunc := funObj.Name()

			// Check for an accompanying CRYPTO-USAGE comment.
			documented, reason := isDocumented(pass, file, call)
			if documented {
				// Report documented usage including the provided rationale.
				pass.Report(analysis.Diagnostic{
					Pos: call.Pos(),
					End: call.End(),
					Message: "cryptographic usage detected: " + cryptoModule + "." + cryptoFunc +
						" documented with CRYPTO-USAGE: " + reason,
				})
			} else {
				// Report missing documentation.
				pass.Report(analysis.Diagnostic{
					Pos: call.Pos(),
					End: call.End(),
					Message: "cryptographic usage detected: " + cryptoModule + "." + cryptoFunc +
						" without CRYPTO-USAGE comment. Please add a comment of the form `CRYPTO-USAGE: <reason>` explaining why it is used.",
				})
			}
			return true
		})
	}
	return nil, nil
}

// isDocumented checks whether there is a CRYPTO-USAGE comment near the node.
func isDocumented(pass *analysis.Pass, file *ast.File, node ast.Node) (bool, string) {
	callPos := pass.Fset.Position(node.Pos())

	// Iterate over all comment groups in the file.
	for _, cg := range file.Comments {
		cgPos := pass.Fset.Position(cg.End())
		// Consider comment groups that end on the same line or on the immediately preceding line.
		if callPos.Line-cgPos.Line <= 1 && callPos.Line-cgPos.Line >= 0 {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "CRYPTO-USAGE:") {
					// Extract the reason after the prefix.
					parts := strings.SplitN(c.Text, "CRYPTO-USAGE:", 2)
					reason := strings.TrimSpace(parts[1])
					return true, reason
				}
			}
		}
	}
	return false, ""
}

func main() {
	// Use singlechecker so this analyzer can be run as a standalone tool
	// or integrated into golangci-lint.
	singlechecker.Main(Analyzer)
}

