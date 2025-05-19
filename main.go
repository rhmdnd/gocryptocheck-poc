// main.go
package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v2"
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

//go:embed crypto_algorithms_open_dataset/definitions_crypto_algorithms/algorithms/**/*.yaml
var algoFS embed.FS
var moduleVersions map[string]string
var excludeDirs []string

var (
	algoKeywordIndex = map[string]interface{}{} // "pkg.Func" → props
	datasetPackages  = map[string]struct{}{}    // quick package-prefix lookup
)

// AlgorithmProps represents the subset we need for CycloneDX mapping.
type AlgorithmProps struct {
	Primitive       string   `yaml:"primitive"`
	CryptoFunctions []string `yaml:"cryptoFunctions"`
}

// algorithmDefinition mirrors the structure of each YAML file.
type algorithmDefinition struct {
	Algorithm           string         `yaml:"algorithm"`
	AlgorithmId         string         `yaml:"algorithmId"`
	Category            string         `yaml:"catagory"`
	Stength             string         `yaml:"strength"`
	Keywords            []string       `yaml:"keywords"`
	AlgorithmProperties AlgorithmProps `yaml:"algorithmProperties"`
}

func initEmbeddedAlgorithms() {
	if err := loadEmbeddedAlgorithms(); err != nil {
		log.Printf("warning: failed to load embedded crypto dataset: %v", err)
	}
	log.Printf("loaded algorithms from embedded crypto dataset")
}

func loadEmbeddedAlgorithms() error {
	return fs.WalkDir(algoFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		data, err := algoFS.ReadFile(path)
		if err != nil {
			return err
		}
		var def algorithmDefinition
		if err := yaml.Unmarshal(data, &def); err != nil {
			return err
		}
		algoKeywordIndex[def.AlgorithmId] = def
		return nil
	})
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
	Module     string            `json:"module"`
	Function   string            `json:"function"`
	Caller     string            `json:"caller"`
	File       string            `json:"file"`
	Line       int               `json:"line"`
	Documented bool              `json:"documented"`
	Reason     string            `json:"reason,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type Property struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

// CycloneDX BOM structure.
type Bom struct {
	BomFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Components  []Component `json:"components"`
}

type Component struct {
	Type             string                 `json:"type"`
	Name             string                 `json:"name"`
	CryptoProperties map[string]interface{} `json:"cryptoProperties,omitempty"`
	Properties       []Property             `json:"properties,omitempty"`
}

func main() {
	outputFormat := flag.String("format", "cyclonedx", "Output format: cyclonedx")
	flag.Func("excludeDir", "directory name to exclude from processing (can repeat)", func(val string) error {
		excludeDirs = append(excludeDirs, val)
		return nil
	})
	flag.Parse()

	initEmbeddedAlgorithms()

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

// getAlgorithmPropsByFunction maps pkg+func → (primitive, cryptoFunctions)
func getAlgorithmPropsByFunction(pkg, fn string) map[string]interface{} {
	props := map[string]interface{}{
		"primitive":       "unknown",
		"cryptoFunctions": []string{"unknown"},
	}

	switch pkg {
	case "crypto/sha1", "crypto/sha256", "crypto/sha512", "crypto/md5":
		props["primitive"], props["cryptoFunctions"] = "hash", []string{"digest"}

	case "crypto/aes", "crypto/des":
		props["primitive"], props["cryptoFunctions"] = "block-cipher", []string{"encrypt", "decrypt"}

	case "crypto/hmac":
		props["primitive"], props["cryptoFunctions"] = "mac", []string{"sign"}

	case "crypto/rand":
		props["primitive"] = "drbg"

	case "crypto/rsa":
		switch fn {
		case "GenerateKey":
			props["primitive"], props["cryptoFunctions"] = "pke", []string{"keygen"}
		case "EncryptOAEP", "DecryptOAEP":
			props["primitive"], props["cryptoFunctions"] = "pke", []string{"encrypt", "decrypt"}
		default:
			props["primitive"], props["cryptoFunctions"] = "signature", []string{"sign"}
		}

	case "crypto/ecdsa", "crypto/ed25519":
		if fn == "GenerateKey" {
			props["primitive"], props["cryptoFunctions"] = "other", []string{"keygen"}
		} else {
			props["primitive"], props["cryptoFunctions"] = "signature", []string{"sign"}
		}
	}

	return props
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
			documented, rationale := findCryptoUsageComment(file, call, fset)

			// ensure metadata map
			metadata := make(map[string]string)

			// make sure we track the module version for additional transparency
			metadata["moduleVersion"] = resolveModuleVersion(pkgPath)

			// inject algorithm info
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

// findCryptoUsageComment looks for *any* comment immediately preceding the node
// and returns (found, commentText).
func findCryptoUsageComment(file *ast.File, node ast.Node, fset *token.FileSet) (bool, string) {
	callPos := fset.Position(node.Pos())
	for _, cg := range file.Comments {
		cgEnd := fset.Position(cg.End())
		// only consider comment groups ending on the same line or one line above
		if callPos.Line-cgEnd.Line >= 0 && callPos.Line-cgEnd.Line <= 1 {
			// join all lines of this comment group (strip the leading // or /* */)
			var lines []string
			for _, c := range cg.List {
				text := c.Text
				// strip comment markers
				if strings.HasPrefix(text, "//") {
					text = strings.TrimSpace(text[2:])
				} else if strings.HasPrefix(text, "/*") {
					text = strings.Trim(text, "/* ")
				}
				lines = append(lines, text)
			}
			return true, strings.Join(lines, "\n")
		}
	}
	return false, ""
}

// outputCycloneDX outputs a CycloneDX BOM in JSON format.
// The metadata (key-value pairs) appear as additional properties.
func outputCycloneDX(usages []CryptoUsage) {
	// build the BOM
	bom := Bom{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.6", // bump to 1.6
		Version:     1,
	}
	for _, usage := range usages {
		compName := usage.Module + "." + usage.Function
		desc := ""
		if usage.Documented {
			desc = usage.Reason
		} else {
			desc = "Undocumented cryptographic usage."
		}

		// Assemble cryptoProperties per 1.6 CycloneDX scheme
		cryptoProps := make(map[string]interface{}, len(usage.Metadata)+1)
		cryptoProps["assetType"] = "algorithm"
		protocolTypes := []string{"tls", "ssh", "ipsec", "ike", "sstp", "wpa"}
		for _, pt := range protocolTypes {
			if contains := strings.Contains(compName, pt); contains {
				cryptoProps["assetType"] = "protocol"
				break
			}
			// otherwise, we'll just assume algorithm
			cryptoProps["assetType"] = "algorithm"
		}

		// Now consolidate file/line/caller into ONE property:
		location := fmt.Sprintf("%s:%d", usage.File, usage.Line)

		compProps := []Property{
			{Name: location, Value: desc},
		}

		// algorithmProperties grouping
		if cryptoProps["assetType"] == "algorithm" {
			algoProps := getAlgorithmPropsByFunction(usage.Module, usage.Function)
			cryptoProps["algorithmProperties"] = algoProps
		}

		for key, value := range usage.Metadata {
			substrings := strings.Split(key, "-")
			if len(substrings) > 2 {
				// fail here
			}
			// extend this to include setting additional attributes
			// for cryptoProperties or algorithmProperties
			if substrings[0] == "properties" {
				compProps = append(compProps, Property{Name: substrings[1], Value: value})
			}
		}

		// TODO: Integrate this into algoKeywordIndex somehow - so that
		// we can use a single data set to classify cryptographic
		// usage.
		component := Component{
			Type:             "cryptographic-asset",
			Name:             compName,
			CryptoProperties: cryptoProps,
			Properties:       compProps,
		}
		bom.Components = append(bom.Components, component)
	}
	out, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling BOM: %v", err)
	}
	fmt.Println(string(out))
}
