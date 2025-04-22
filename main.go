// main.go
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// cryptoPackages lists known cryptographic package identifiers.
// A package path is considered cryptographic if it is exactly equal to one of these entries
// or if it is a subpackage of one (e.g. "golang.org/x/crypto/..." is covered by "golang.org/x/crypto").
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
	"golang.org/x/crypto",
	"github.com/cloudflare/circl",
	"github.com/minio/minio-go",
}

var moduleVersions map[string]string
var excludeDirs []string // populated via flag

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
	Module     string            `json:"module"`
	Function   string            `json:"function"`
	Caller     string            `json:"caller"`
	File       string            `json:"file"`
	Line       int               `json:"line"`
	Documented bool              `json:"documented"`
	Reason     string            `json:"reason,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// CycloneDX BOM structure.
type Bom struct {
	BomFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Components  []Component `json:"components"`
}

type Component struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	File        string            `json:"file"`
	Line        int               `json:"line"`
	Properties  map[string]string `json:"properties,omitempty"`
}

func main() {
	outputFormat := flag.String("format", "cyclonedx", "Output format: cyclonedx, spdx, or text")
	flag.Func("excludeDir", "directory name to exclude from processing (can repeat)", func(val string) error {
		excludeDirs = append(excludeDirs, val)
		return nil
	})
	flag.Parse()

	var err error
	moduleVersions, err = loadModuleVersions()
	if err != nil {
		log.Printf("Warning: couldn’t load module versions: %v", err)
		moduleVersions = map[string]string{}
	}

	// Use positional arguments as target patterns; if none provided, default to current directory.
	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = []string{"."}
	}

	var allUsages []CryptoUsage
	// Process each glob pattern.
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			log.Fatalf("Error with pattern %s: %v", pattern, err)
		}
		for _, match := range matches {
			// skip any match whose path contains one of the excluded dir names
			clean := filepath.Clean(match)
			parts := strings.Split(clean, string(os.PathSeparator))
			skip := false
			for _, ex := range excludeDirs {
				for _, seg := range parts {
					if seg == ex {
						skip = true
						break
					}
				}
				if skip {
					break
				}
			}
			if skip {
				continue
			}

			info, err := os.Stat(match)
			if err != nil {
				log.Fatalf("Error stating %s: %v", match, err)
			}
			if info.IsDir() {
				usages, err := scanDirectory(match)
				if err != nil {
					log.Fatalf("Error scanning directory %s: %v", match, err)
				}
				allUsages = append(allUsages, usages...)
			} else if strings.HasSuffix(match, ".go") {
				usages, err := scanFile(match)
				if err != nil {
					log.Fatalf("Error scanning file %s: %v", match, err)
				}
				allUsages = append(allUsages, usages...)
			}
		}
	}

	// Output the results in the selected format.
	switch *outputFormat {
	case "cyclonedx":
		outputCycloneDX(allUsages)
	case "spdx":
		outputSpdx(allUsages)
	case "text":
		outputText(allUsages)
	default:
		log.Fatalf("Unknown output format: %s", *outputFormat)
	}
}

func loadModuleVersions() (map[string]string, error) {
	// 1) First, get everything from 'go list -m -json all'
	cmd := exec.Command("go", "list", "-mod=mod", "-json", "all")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	versions := make(map[string]string)
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var mod struct {
			Path    string
			Version string
		}
		if err := dec.Decode(&mod); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		versions[mod.Path] = mod.Version
	}

	// 2) Now, look for a vendor/modules.txt and parse missing entries
	if f, err := os.Open("vendor/modules.txt"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			// vendor/modules.txt lists modules like:
			//   # github.com/foo/bar v1.2.3
			if strings.HasPrefix(line, "# ") {
				fields := strings.Fields(line[2:])
				if len(fields) >= 2 {
					modPath, version := fields[0], fields[1]
					if _, exists := versions[modPath]; !exists {
						versions[modPath] = version
					}
				}
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("warning: error reading vendor/modules.txt: %v", err)
		}
	}
	return versions, nil
}

// find the best‐matching module for this pkgPath
func resolveModuleVersion(pkgPath string) string {
	bestLen := 0
	ver := "unknown"
	for modPath, mv := range moduleVersions {
		if pkgPath == modPath || strings.HasPrefix(pkgPath, modPath+"/") {
			if len(modPath) > bestLen {
				bestLen = len(modPath)
				ver = mv
			}
		}
	}

	// If it's a std‑lib import (first segment contains no dot), use Go version
	parts := strings.Split(pkgPath, "/")
	if len(parts) > 0 && !strings.Contains(parts[0], ".") {
		return runtime.Version()
	}
	return ver
}

// helper: map pkg+func → (algorithm name, cryptography type)
func getAlgType(pkgPath, funcName string) (string, string) {
	switch pkgPath {
	case "crypto/sha1":
		return "SHA-1", "Message Digest"
	case "crypto/sha256":
		return "SHA-256", "Message Digest"
	case "crypto/sha512":
		return "SHA-512", "Message Digest"
	case "crypto/md5":
		return "MD5", "Message Digest"
	case "crypto/aes":
		return "AES", "Symmetric Encryption"
	case "crypto/des":
		return "DES", "Symmetric Encryption"
	case "crypto/hmac":
		return "HMAC", "Message Authentication Code"
	case "crypto/rand":
		return "CSPRNG", "Random Number Generation"
	case "crypto/rsa":
		switch funcName {
		case "GenerateKey":
			return "RSA", "Asymmetric Key Generation"
		case "EncryptOAEP", "DecryptOAEP":
			return "RSA-OAEP", "Asymmetric Encryption/Decryption"
		case "SignPSS":
			return "RSA-PSS", "Digital Signature"
		case "SignPKCS1v15", "VerifyPKCS1v15":
			return "RSA", "Digital Signature"
		}
		return "RSA", "Asymmetric Cryptography"
	case "crypto/ecdsa":
		switch funcName {
		case "GenerateKey":
			return "ECDSA", "Asymmetric Key Generation"
		case "Sign":
			return "ECDSA", "Digital Signature"
		case "Verify":
			return "ECDSA", "Signature Verification"
		}
		return "ECDSA", "Asymmetric Cryptography"
	case "crypto/ed25519":
		switch funcName {
		case "GenerateKey":
			return "Ed25519", "Asymmetric Key Generation"
		case "Sign":
			return "Ed25519", "Digital Signature"
		case "Verify":
			return "Ed25519", "Signature Verification"
		}
		return "Ed25519", "Asymmetric Cryptography"
	}
	// fallback: derive a name from the last path segment
	parts := strings.Split(pkgPath, "/")
	return strings.ToUpper(parts[len(parts)-1]), "Unknown"
}

// scanDirectory recursively scans a directory for Go files, skipping vendor directories.
func scanDirectory(dir string) ([]CryptoUsage, error) {
	var usages []CryptoUsage
	fset := token.NewFileSet()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip any user‑excluded dir
		for _, ex := range excludeDirs {
			if info.IsDir() && info.Name() == ex {
				return filepath.SkipDir
			}
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".go") {
			fileUsages, err := scanFilePath(fset, path)
			if err != nil {
				return err
			}
			usages = append(usages, fileUsages...)
		}
		return nil
	})
	return usages, err
}

// scanFile scans a single .go file given its path.
func scanFile(path string) ([]CryptoUsage, error) {
	fset := token.NewFileSet()
	return scanFilePath(fset, path)
}

// scanFilePath parses a file and inspects it for cryptographic usage.
func scanFilePath(fset *token.FileSet, path string) ([]CryptoUsage, error) {
	var usages []CryptoUsage
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	// Iterate over top‑level declarations to find functions
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		caller := fn.Name.Name

		// Inspect only within this function’s body
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}

			// Find matching import to get pkgPath
			var pkgPath string
			for _, imp := range file.Imports {
				impPath := strings.Trim(imp.Path.Value, `"`)
				impName := ""
				if imp.Name != nil {
					impName = imp.Name.Name
				} else {
					parts := strings.Split(impPath, "/")
					impName = parts[len(parts)-1]
				}
				if ident.Name == impName {
					pkgPath = impPath
					break
				}
			}
			if pkgPath == "" || !isCryptoPackage(pkgPath) {
				return true
			}

			pos := fset.Position(call.Pos())
			documented, rationale, metadata := findCryptoUsageComment(file, call, fset)

			// ensure metadata map
			if metadata == nil {
				metadata = make(map[string]string)
			}

			// make sure we track the module version for additional transparency
			metadata["moduleVersion"] = resolveModuleVersion(pkgPath)

			// inject algorithm info
			alg, ctype := getAlgType(pkgPath, sel.Sel.Name)
			metadata["algorithm"] = alg
			metadata["cryptographyType"] = ctype
			metadata["callingFunction"] = caller

			usages = append(usages, CryptoUsage{
				Module:     pkgPath,
				Function:   sel.Sel.Name,
				Caller:     caller,
				File:       path,
				Line:       pos.Line,
				Documented: documented,
				Reason:     rationale,
				Metadata:   metadata,
			})
			return true
		})
	}

	return usages, nil
}

// findCryptoUsageComment searches for a gocryptocheck comment near the AST node.
// It returns whether a comment was found, the rationale text (the first segment),
// and any additional key-value pairs parsed from subsequent segments.
// Format: gocryptocheck: <rationale>[; key: value; ...]
func findCryptoUsageComment(file *ast.File, node ast.Node, fset *token.FileSet) (bool, string, map[string]string) {
	nodePos := fset.Position(node.Pos())
	for _, cg := range file.Comments {
		cgPos := fset.Position(cg.End())
		// Consider comments ending on the same line or immediately preceding the node.
		if nodePos.Line-cgPos.Line <= 1 && nodePos.Line-cgPos.Line >= 0 {
			for _, comment := range cg.List {
				if strings.Contains(comment.Text, "gocryptocheck:") {
					parts := strings.SplitN(comment.Text, "gocryptocheck:", 2)
					commentContent := strings.TrimSpace(parts[1])
					segments := strings.Split(commentContent, ";")
					if len(segments) == 0 {
						return true, "", nil
					}
					// The first segment is the rationale.
					rationale := strings.TrimSpace(segments[0])
					metadata := make(map[string]string)
					// Process additional segments for key-value pairs.
					for _, seg := range segments[1:] {
						seg = strings.TrimSpace(seg)
						if seg == "" {
							continue
						}
						kv := strings.SplitN(seg, ":", 2)
						if len(kv) == 2 {
							key := strings.TrimSpace(kv[0])
							value := strings.TrimSpace(kv[1])
							metadata[key] = value
						}
					}
					return true, rationale, metadata
				}
			}
		}
	}
	return false, "", nil
}

// outputCycloneDX outputs a CycloneDX BOM in JSON format.
// The metadata (key-value pairs) appear as additional properties.
func outputCycloneDX(usages []CryptoUsage) {
	var components []Component
	for _, usage := range usages {
		compName := usage.Module + "." + usage.Function
		desc := ""
		if usage.Documented {
			desc = "Documented: " + usage.Reason
		} else {
			desc = "Undocumented cryptographic usage. Please add a comment of the form `gocryptocheck: <rationale>[; key: value...]`."
		}
		component := Component{
			Type:        "module",
			Name:        compName,
			Description: desc,
			File:        usage.File,
			Line:        usage.Line,
		}

		// Add metadata as separate properties if present.
		props := make(map[string]string, len(usage.Metadata)+1)
		props["callingFunction"] = usage.Caller
		for k, v := range usage.Metadata {
			props[k] = v
		}

		component.Properties = props
		components = append(components, component)
	}
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

// outputText outputs a plain text report.
// It prints the rationale first and then each metadata key-value pair on separate lines.
func outputText(usages []CryptoUsage) {
	for _, usage := range usages {
		docStatus := "Undocumented"
		if usage.Documented {
			docStatus = "Documented: " + usage.Reason
		}
		fmt.Printf("%s:%d: %s.%s - %s\n", usage.File, usage.Line, usage.Module, usage.Function, docStatus)
		// Print additional metadata if present.
		if len(usage.Metadata) > 0 {
			fmt.Println("  Additional details:")
			for key, value := range usage.Metadata {
				fmt.Printf("    %s: %s\n", key, value)
			}
		}
	}
}

// outputSpdx outputs an SPDX document in tag‑value format.
// The metadata is output as additional package details after the main package description.
func outputSpdx(usages []CryptoUsage) {
	created := time.Now().Format(time.RFC3339)
	namespace := fmt.Sprintf("http://spdx.org/spdxdocs/gocryptocheck-%d", time.Now().Unix())
	fmt.Println("SPDXVersion: SPDX-2.2")
	fmt.Println("DataLicense: CC0-1.0")
	fmt.Println("SPDXID: SPDXRef-DOCUMENT")
	fmt.Println("DocumentName: gocryptocheck Cryptographic Usage SPDX Report")
	fmt.Println("DocumentNamespace: " + namespace)
	fmt.Println("Creator: Tool: gocryptocheck")
	fmt.Println("Created: " + created)
	fmt.Println()
	// For each cryptographic usage, output a Package entry.
	for _, usage := range usages {
		packageName := usage.Module + "." + usage.Function
		// Sanitize SPDXID by replacing slashes or spaces.
		spdxID := fmt.Sprintf("SPDXRef-%s-%d", strings.ReplaceAll(packageName, "/", "."), usage.Line)
		desc := ""
		if usage.Documented {
			desc = "Documented: " + usage.Reason
		} else {
			desc = "Undocumented cryptographic usage. Please add a comment of the form `gocryptocheck: <rationale>[; key: value...]`."
		}
		fmt.Printf("##### Cryptographic usage found in %s at line %d\n", usage.File, usage.Line)
		fmt.Println("PackageName: " + packageName)
		fmt.Println("SPDXID: " + spdxID)
		for key, _ := range usage.Metadata {
			if key == "moduleVersion" {
				fmt.Println("PackageVersion: " + usage.Metadata[key])
			}
		}
		fmt.Println("PackageDownloadLocation: NOASSERTION")
		fmt.Println("PackageDescription: " + desc)
		// Output additional metadata as separate lines.
		if len(usage.Metadata) > 0 {
			for key, value := range usage.Metadata {
				// We've already documented this above
				if key == "moduleVersion" {
					continue
				}
				fmt.Printf("PackageComment: %s: %s\n", key, value)
			}
		}
		fmt.Println()
	}
}
