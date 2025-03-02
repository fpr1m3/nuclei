package file

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/internal/severity"
	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
)

func TestFindInputPaths(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-file"
	request := &Request{
		ID:                templateID,
		MaxSize:           1024,
		NoRecursive:       false,
		Extensions:        []string{"all", ".lock"},
		ExtensionDenylist: []string{".go"},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.SeverityHolder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	tempDir, err := ioutil.TempDir("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempDir)

	files := map[string]string{
		"test.go":           "TEST",
		"config.yaml":       "TEST",
		"final.yaml":        "TEST",
		"image_ignored.png": "TEST",
		"test.js":           "TEST",
	}
	for k, v := range files {
		err = ioutil.WriteFile(filepath.Join(tempDir, k), []byte(v), 0777)
		require.Nil(t, err, "could not write temporary file")
	}
	expected := []string{"config.yaml", "final.yaml", "test.js"}
	got := []string{}
	err = request.getInputPaths(tempDir+"/*", func(item string) {
		base := filepath.Base(item)
		got = append(got, base)
	})
	require.Nil(t, err, "could not get input paths for glob")
	require.ElementsMatch(t, expected, got, "could not get correct file matches for glob")

	got = []string{}
	err = request.getInputPaths(tempDir, func(item string) {
		base := filepath.Base(item)
		got = append(got, base)
	})
	require.Nil(t, err, "could not get input paths for directory")
	require.ElementsMatch(t, expected, got, "could not get correct file matches for directory")
}
