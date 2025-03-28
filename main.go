// main.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strings"
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

// CryptoUsage represents one instance of cryptographic usage.
type CryptoUsage struct {
	Module     string `json:"module"`
	Function   string `json:"function"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Documented bool   `json:"documented"`
	Reason     string `json:"reason,omitempty"`
}

// CycloneDX BOM structure.
type Bom struct {
	BomFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Components  []Component `json:"components"`
}

// Component represents a component entry in the BOM.
type Component struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	File        string `json:"file"`
	Line        int    `json:"line"`
}

func main() {
	// Directory to scan (defaults to current directory).
	dir := flag.String("dir", ".", "directory to scan for Go files")
	flag.Parse()

	usages, err := scanDirectory(*dir)
	if err != nil {
		log.Fatalf("Error scanning directory: %v", err)
	}

	// Convert each cryptographic usage to a CycloneDX BOM component.
	var components []Component
	for _, usage := range usages {
		compName := usage.Module + "." + usage.Function
		desc := ""
		if usage.Documented {
			desc = "Documented: CRYPTO-USAGE: " + usage.Reason
		} else {
			desc = "Undocumented cryptographic usage. Please add a comment of the form `CRYPTO-USAGE: <reason>`."
		}
		components = append(components, Component{
			Type:        "library",
			Name:        compName,
			Description: desc,
			File:        usage.File,
			Line:        usage.Line,
		})
	}

	// Build the BOM.
	bom := Bom{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
		Components:  components,
	}

	out, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling BOM: %v", err)
	}
	fmt.Println(string(out))
}

// scanDirectory recursively scans the given directory for Go source files and returns any cryptographic usages found.
func scanDirectory(dir string) ([]CryptoUsage, error) {
	var usages []CryptoUsage

	fset := token.NewFileSet()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip vendor and only focus on cryptographic usage within the project
		if info.IsDir() && info.Name() == "vendor" {
			return filepath.SkipDir
		}

		// Only process .go files.
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		fileUsages := scanFile(fset, file, path)
		usages = append(usages, fileUsages...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return usages, nil
}

// scanFile inspects a parsed file for call expressions from cryptographic packages.
func scanFile(fset *token.FileSet, file *ast.File, filename string) []CryptoUsage {
	var usages []CryptoUsage

	ast.Inspect(file, func(n ast.Node) bool {
		// We're interested in call expressions.
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// We expect cryptographic calls to appear as selector expressions (e.g. pkg.Func).
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		// The receiver should be an identifier matching one of the imported packages.
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		// Determine the package path from the file's imports.
		var pkgPath string
		for _, imp := range file.Imports {
			var impName string
			// If the import has an explicit name use it.
			if imp.Name != nil {
				impName = imp.Name.Name
			} else {
				// Otherwise use the default name: the base element of the path.
				impPath := strings.Trim(imp.Path.Value, "\"")
				parts := strings.Split(impPath, "/")
				impName = parts[len(parts)-1]
			}
			if ident.Name == impName {
				pkgPath = strings.Trim(imp.Path.Value, "\"")
				break
			}
		}
		if pkgPath == "" || !isCryptoPackage(pkgPath) {
			return true
		}

		pos := fset.Position(call.Pos())
		documented, reason := findCryptoUsageComment(file, call, fset)
		usage := CryptoUsage{
			Module:     pkgPath,
			Function:   sel.Sel.Name,
			File:       filename,
			Line:       pos.Line,
			Documented: documented,
			Reason:     reason,
		}
		usages = append(usages, usage)
		return true
	})
	return usages
}

// findCryptoUsageComment looks for a CRYPTO-USAGE comment near the given AST node.
func findCryptoUsageComment(file *ast.File, node ast.Node, fset *token.FileSet) (bool, string) {
	nodePos := fset.Position(node.Pos())
	for _, cg := range file.Comments {
		cgPos := fset.Position(cg.End())
		// Look for comments ending on the same line or immediately before the node.
		if nodePos.Line-cgPos.Line <= 1 && nodePos.Line-cgPos.Line >= 0 {
			for _, comment := range cg.List {
				if strings.Contains(comment.Text, "CRYPTO-USAGE:") {
					parts := strings.SplitN(comment.Text, "CRYPTO-USAGE:", 2)
					return true, strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return false, ""
}
