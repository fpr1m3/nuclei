package model

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/nuclei/v2/internal/severity"
	"github.com/stretchr/testify/assert"
)

func TestInfoJsonMarshal(t *testing.T) {
	info := Info{
		Name:           "Test Template Name",
		Authors:        StringSlice{[]string{"forgedhallpass", "ice3man"}},
		Description:    "Test description",
		SeverityHolder: severity.SeverityHolder{Severity: severity.High},
		Tags:           StringSlice{[]string{"cve", "misc"}},
		Reference:      StringSlice{"reference1"},
	}

	result, err := json.Marshal(&info)
	assert.Nil(t, err)

	expected := `{"name":"Test Template Name","author":["forgedhallpass","ice3man"],"tags":["cve","misc"],"description":"Test description","reference":"reference1","severity":"high"}`
	assert.Equal(t, expected, string(result))
}

func TestInfoYamlMarshal(t *testing.T) {
	info := Info{
		Name:           "Test Template Name",
		Authors:        StringSlice{[]string{"forgedhallpass", "ice3man"}},
		Description:    "Test description",
		SeverityHolder: severity.SeverityHolder{Severity: severity.High},
		Tags:           StringSlice{[]string{"cve", "misc"}},
		Reference:      StringSlice{"reference1"},
	}

	result, err := yaml.Marshal(&info)
	assert.Nil(t, err)

	expected := `name: Test Template Name
author:
- forgedhallpass
- ice3man
tags:
- cve
- misc
description: Test description
reference: reference1
severity: high
`
	assert.Equal(t, expected, string(result))
}

func TestUnmarshal(t *testing.T) {
	templateName := "Test Template"
	authors := []string{"forgedhallpass", "ice3man"}
	tags := []string{"cve", "misc"}
	references := []string{"http://test.com", "http://domain.com"}

	dynamicKey1 := "customDynamicKey1"
	dynamicKey2 := "customDynamicKey2"

	dynamicKeysMap := map[string]string{
		dynamicKey1: "customDynamicValue1",
		dynamicKey2: "customDynamicValue2",
	}

	assertUnmarshalledTemplateInfo := func(t *testing.T, yamlPayload string) Info {
		info := Info{}
		err := yaml.Unmarshal([]byte(yamlPayload), &info)
		assert.Nil(t, err)
		assert.Equal(t, info.Name, templateName)
		assert.Equal(t, info.Authors.ToSlice(), authors)
		assert.Equal(t, info.Tags.ToSlice(), tags)
		assert.Equal(t, info.SeverityHolder.Severity, severity.Critical)
		assert.Equal(t, info.Reference.ToSlice(), references)
		assert.Equal(t, info.AdditionalFields, dynamicKeysMap)
		return info
	}

	yamlPayload1 := `
  name: ` + templateName + `
  author: ` + strings.Join(authors, ", ") + `
  tags: ` + strings.Join(tags, ", ") + `
  severity: critical
  reference: ` + strings.Join(references, ", ") + `
  additional-fields:
     ` + dynamicKey1 + `: ` + dynamicKeysMap[dynamicKey1] + `
     ` + dynamicKey2 + `: ` + dynamicKeysMap[dynamicKey2] + `
`
	yamlPayload2 := `
  name: ` + templateName + `
  author:
    - ` + authors[0] + `
    - ` + authors[1] + `
  tags:
    - ` + tags[0] + `
    - ` + tags[1] + `
  severity: critical
  reference:
    - ` + references[0] + ` # comments are not unmarshalled
    - ` + references[1] + `
  additional-fields:
     ` + dynamicKey1 + `: ` + dynamicKeysMap[dynamicKey1] + `
     ` + dynamicKey2 + `: ` + dynamicKeysMap[dynamicKey2] + `
`

	info1 := assertUnmarshalledTemplateInfo(t, yamlPayload1)
	info2 := assertUnmarshalledTemplateInfo(t, yamlPayload2)
	assert.Equal(t, info1, info2)
}
