package invagent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ErrForeignConfig reports an agent configured for another ingest endpoint:
// the client never repoints an agent an operator set up by hand.
var ErrForeignConfig = errors.New("invagent: the inventory agent is configured for another ingest endpoint")

// AgentSettings are the agent.yaml values the client manages.
type AgentSettings struct {
	Ingest     string
	KeyID      string
	KeyFile    string
	CAFile     string
	ServerName string
}

// Default agent paths when the file lacks them.
const (
	defaultCredentialFile = "/var/lib/inventory-agent/credential"
	defaultStateFile      = "/var/lib/inventory-agent/state.json"
)

// Configure sets ingest_endpoint, auto_enroll and the optional TLS settings
// in the agent's YAML config at path, keeping everything else (comments
// included). A missing file is created. It reports whether the file changed.
func Configure(path string, s AgentSettings) (bool, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed agent config path
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	var doc yaml.Node
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return false, fmt.Errorf("invagent: %s: %w", path, err)
		}
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return false, fmt.Errorf("invagent: %s: not a YAML mapping", path)
	}
	root := doc.Content[0]
	if cur := scalar(root, "ingest_endpoint"); cur != "" && cur != s.Ingest {
		return false, fmt.Errorf("%w (%s)", ErrForeignConfig, cur)
	}
	setScalar(root, "ingest_endpoint", s.Ingest)
	if scalar(root, "credential_file") == "" {
		setScalar(root, "credential_file", defaultCredentialFile)
	}
	if scalar(root, "state_file") == "" {
		setScalar(root, "state_file", defaultStateFile)
	}
	if s.CAFile != "" {
		setScalar(root, "ca_file", s.CAFile)
	}
	if s.ServerName != "" {
		setScalar(root, "server_name", s.ServerName)
	}
	auto := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	setScalar(auto, "key_id", s.KeyID)
	setScalar(auto, "key_file", s.KeyFile)
	setNode(root, "auto_enroll", auto)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return false, err
	}
	_ = enc.Close()
	if bytes.Equal(buf.Bytes(), raw) {
		return false, nil
	}
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	return true, writeAtomic(path, buf.Bytes(), mode)
}

func find(m *yaml.Node, key string) (int, bool) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i, true
		}
	}
	return 0, false
}

func scalar(m *yaml.Node, key string) string {
	if i, ok := find(m, key); ok && m.Content[i+1].Kind == yaml.ScalarNode {
		return m.Content[i+1].Value
	}
	return ""
}

func setScalar(m *yaml.Node, key, value string) {
	setNode(m, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}

func setNode(m *yaml.Node, key string, v *yaml.Node) {
	if i, ok := find(m, key); ok {
		v.LineComment = m.Content[i+1].LineComment
		m.Content[i+1] = v
		return
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

// writeAtomic writes data to path through a temporary file in the same
// directory (created 0755 when missing).
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- /etc/inventory-agent is world-readable, secrets live in 0600 files
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tangra-client-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
