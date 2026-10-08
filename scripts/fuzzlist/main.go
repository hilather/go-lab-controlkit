// Command fuzzlist prints every Go fuzz target in this module.
// A target is a function whose signature is FuzzXxx(f *testing.F),
// including a signature that spans more than one line.
// With no arguments it also checks the required names and exits non-zero
// when the module has no targets or a required name is missing.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// requiredTargets are the fuzz functions section 7 names.
var requiredTargets = []string{
	"FuzzAuthorization",
	"FuzzOrigin",
	"FuzzCheck",
}

// Target is one fuzz function and the package directory that holds it,
// relative to the scan root, using forward slashes.
type Target struct {
	Dir  string
	Name string
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	found, err := Targets(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fuzzlist: %v\n", err)
		os.Exit(1)
	}
	if err := Validate(found, requiredTargets); err != nil {
		fmt.Fprintf(os.Stderr, "fuzzlist: %v\n", err)
		os.Exit(1)
	}
	for _, t := range found {
		fmt.Printf("%s\t%s\n", t.Dir, t.Name)
	}
}

// Targets parses every *_test.go under root, skipping .git, and returns
// the fuzz functions in stable order.
func Targets(root string) ([]Target, error) {
	var out []Target
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (d.Name() == ".git" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		names, err := fuzzFuncs(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		for _, name := range names {
			out = append(out, Target{Dir: rel, Name: name})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir < out[j].Dir
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Validate fails when found is empty or any required name is absent.
func Validate(found []Target, required []string) error {
	if len(found) == 0 {
		return fmt.Errorf("no fuzz targets")
	}
	have := map[string]bool{}
	for _, t := range found {
		have[t.Name] = true
	}
	var missing []string
	for _, name := range required {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required targets: %s", strings.Join(missing, ", "))
	}
	return nil
}

func fuzzFuncs(path string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Type.Params == nil {
			continue
		}
		if !strings.HasPrefix(fn.Name.Name, "Fuzz") {
			continue
		}
		if !fuzzParam(fn.Type.Params) {
			continue
		}
		names = append(names, fn.Name.Name)
	}
	return names, nil
}

func fuzzParam(list *ast.FieldList) bool {
	if list == nil || len(list.List) != 1 || len(list.List[0].Names) != 1 {
		return false
	}
	star, ok := list.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "testing" && sel.Sel.Name == "F"
}
