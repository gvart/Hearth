// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/gvart/hearth/internal/policy"
)

// Why a file cannot be saved.
var (
	// ErrNotFound is an automation no file of the directory defines.
	ErrNotFound = errors.New("no such automation")
	// ErrExists is a new automation whose id or file name is already in use.
	ErrExists = errors.New("automation already exists")
	// ErrRevision is a save based on content the file no longer has.
	ErrRevision = errors.New("the file changed since it was read")
	// ErrDirInvalid is a save the hub could not load: another file of the
	// directory is invalid, and one invalid file refuses the whole reload.
	ErrDirInvalid = errors.New("the automations directory does not load")
	// ErrNotRegular is a file that is not a regular file, such as a symlink
	// into a git checkout: replacing it would cut that link.
	ErrNotRegular = errors.New("not a regular file")
)

// ValidID reports whether id is a well-formed automation id. A valid id holds
// no path separator or dot, so it can name a file in the directory.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Revision identifies the content of an automation file.
func Revision(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Problem is one thing wrong with an automation file. Line is 0 when the
// problem has no line.
type Problem struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// yamlLine finds the line in an error of the YAML parser.
var yamlLine = regexp.MustCompile(`line (\d+)`)

// Problems lists what err, from Parse, says is wrong.
func Problems(err error) []Problem {
	var le *LoadError
	if !errors.As(err, &le) {
		return []Problem{{Message: err.Error()}}
	}
	out := make([]Problem, 0, len(le.Errs))
	for _, e := range le.Errs {
		var at *lineErr
		if errors.As(e, &at) {
			out = append(out, Problem{Line: at.line, Message: at.msg})
			continue
		}
		p := Problem{Message: e.Error()}
		if m := yamlLine.FindStringSubmatch(p.Message); m != nil {
			p.Line, _ = strconv.Atoi(m[1])
		}
		out = append(out, p)
	}
	return out
}

// File is one automation file of a directory, valid or not.
type File struct {
	// Path is where it is.
	Path string
	// ID is the id it declares, valid or not; "" if it declares none.
	ID      string
	Content []byte
	// Automation is the loaded file, nil when Err is set.
	Automation *Automation
	// Err says why the hub cannot load it.
	Err error
	// Linked is a file that is not a regular file of the directory, such as
	// a symlink. The hub loads what it points to, so its id and validity
	// count, but Content is empty: what is outside the directory stays there.
	Linked bool
}

// Files reads and writes the automation files of a directory, as the hub
// that loads them would judge them.
type Files struct {
	Dir   string
	Kinds Kinds
}

// List reads every automation file. A file repeating the id of an earlier
// one is invalid, as it is to the hub.
func (f Files) List() ([]File, error) {
	paths, err := automationFiles(f.Dir)
	if err != nil {
		return nil, err
	}
	out := make([]File, 0, len(paths))
	seen := map[string]string{}
	for _, path := range paths {
		linked, readable, err := linkState(path)
		if err != nil {
			return nil, err
		}
		if !readable {
			out = append(out, File{Path: path, Linked: true, Err: ErrNotRegular})
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read automation file: %w", err)
		}
		file := File{Path: path, ID: declaredID(b), Content: b, Linked: linked}
		file.Automation, file.Err = Parse(filepath.Base(path), b, f.Kinds)
		if linked {
			file.Content = nil
			if file.Err != nil {
				file.Err = ErrNotRegular // its problems would quote the target
			}
		}
		if prev, dup := seen[file.ID]; dup && file.ID != "" && file.Err == nil {
			file.Automation, file.Err = nil, fmt.Errorf("automation id %q is already used by %s", file.ID, filepath.Base(prev))
		}
		if file.ID != "" && seen[file.ID] == "" {
			seen[file.ID] = path
		}
		out = append(out, file)
	}
	return out, nil
}

// linkState reports whether path is something other than a regular file, and
// whether it can be read without blocking: a named pipe would never answer.
func linkState(path string) (linked, readable bool, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, false, fmt.Errorf("check automation file: %w", err)
	}
	if info.Mode().IsRegular() {
		return false, true, nil
	}
	target, err := os.Stat(path)
	return true, err == nil && target.Mode().IsRegular(), nil
}

// declaredID is the id a file declares, read without validating the rest of
// it, so that an invalid file can still be found and repaired.
func declaredID(b []byte) string {
	var doc struct {
		ID yaml.Node `yaml:"id"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil || doc.ID.Kind != yaml.ScalarNode {
		return ""
	}
	return doc.ID.Value
}

// Get returns the file that defines the automation id.
func (f Files) Get(id string) (File, error) {
	if !ValidID(id) {
		return File{}, fmt.Errorf("automation %q: %w", id, ErrNotFound)
	}
	files, err := f.List()
	if err != nil {
		return File{}, err
	}
	for _, file := range files {
		if file.ID == id {
			if file.Linked {
				return File{}, fmt.Errorf("automation %s: %w", id, ErrNotRegular)
			}
			return file, nil
		}
	}
	return File{}, fmt.Errorf("automation %s: %w", id, ErrNotFound)
}

// Target returns the file saving a, the new content of the automation a.ID,
// would write, or says why it must not be saved. With create, a is a new
// automation, written to <id>.yaml; otherwise it replaces the file that
// defines a.ID, which must still have the content revision names. The path
// comes from the directory's listing, or from a.ID, which Parse has
// validated: never from a request.
func (f Files) Target(a *Automation, create bool, revision string) (string, error) {
	files, err := f.List()
	if err != nil {
		return "", err
	}
	path := ""
	var broken []error
	for _, file := range files {
		switch {
		case file.ID == a.ID && path == "":
			if create {
				return "", fmt.Errorf("automation %s is defined in %s: %w", a.ID, filepath.Base(file.Path), ErrExists)
			}
			if file.Linked {
				return "", fmt.Errorf("%s: %w", filepath.Base(file.Path), ErrNotRegular)
			}
			if Revision(file.Content) != revision {
				return "", fmt.Errorf("automation %s: %w", a.ID, ErrRevision)
			}
			path = file.Path
		case file.Err != nil:
			broken = append(broken, fmt.Errorf("%s: %w", filepath.Base(file.Path), file.Err))
		}
	}
	if len(broken) > 0 {
		return "", fmt.Errorf("%w: %w", ErrDirInvalid, errors.Join(broken...))
	}
	if !create {
		if path == "" {
			return "", fmt.Errorf("automation %s: %w", a.ID, ErrNotFound)
		}
	} else {
		path = filepath.Join(f.Dir, a.ID+".yaml")
		// A file may be named after an id it does not declare.
		if _, err := os.Lstat(path); err == nil {
			return "", fmt.Errorf("file %s.yaml holds another automation: %w", a.ID, ErrExists)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("check automation file: %w", err)
		}
		return path, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("check automation file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s: %w", filepath.Base(path), ErrNotRegular)
	}
	return path, nil
}

// WriteFile writes b to path, a file of dir, in one step: the hub's reload
// sees the old content or the new, never part of it. A file it replaces
// keeps its permissions; a new one is private to the hub's user.
func WriteFile(dir, path string, b []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create automations dir: %w", err)
	}
	// The name is neither *.yaml nor *.yml, so a reload never reads it.
	tmp, err := os.CreateTemp(dir, ".apply-*")
	if err != nil {
		return fmt.Errorf("write automation: %w", err)
	}
	defer os.Remove(tmp.Name())
	if info, err := os.Stat(path); err == nil {
		if err := tmp.Chmod(info.Mode().Perm()); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("write automation: %w", err)
		}
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write automation: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write automation: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write automation: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write automation: %w", err)
	}
	return nil
}

// SaveEngine returns the engine that decides on saving p, written by an actor
// of kind. When e would let p run a dangerous action with nobody asked, by a
// grant to its id or by a mode, saving the file is the last moment a person
// can see what it does: the save is approved by a person, whatever the modes
// say about saves by kind.
//
// A plugin_command counts as dangerous here, whatever the saving hub's
// manifest says: another hub of a cluster may declare it dangerous and run it.
func SaveEngine(e *policy.Engine, kind string, p *Automation) *policy.Engine {
	for _, s := range p.Actions {
		action := s.Impl.Policy()
		if _, ok := s.Impl.(*pluginAction); ok {
			action = policy.PluginCommandDangerous
		}
		if class, _ := policy.ClassOf(action); class != policy.Dangerous {
			continue
		}
		run := policy.Request{ActorKind: policy.ActorAutomation, ActorID: p.ID, Action: action}
		if decision, _ := e.Check(run); decision == policy.Allow {
			return e.Holding(kind, policy.Dangerous)
		}
	}
	return e
}
