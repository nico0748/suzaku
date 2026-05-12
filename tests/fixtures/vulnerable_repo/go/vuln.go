// Intentionally vulnerable Go fixture for Suzaku Compass tests.
// DO NOT use this code. It exists only as scanner bait.

package vuln

import (
	"encoding/gob"
	"html/template"
	"os/exec"
	"path/filepath"
	"strings"
)

func UnsafeShell(userInput string) {
	exec.Command("sh", "-c", userInput).Run()
}

func UnsafeJoin(root, userPath string) string {
	return filepath.Join(root, userPath)
}

func UnsafeTemplate(userInput string) template.HTML {
	return template.HTML(userInput)
}

func UnsafeGob(payload []byte) (interface{}, error) {
	var result interface{}
	dec := gob.NewDecoder(strings.NewReader(string(payload)))
	err := dec.Decode(&result)
	return result, err
}
