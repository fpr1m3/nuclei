package msfrpc

import (
	"github.com/fpr1m3/go-msf-rpc/rpc"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

// Basing on network right now...

type Request struct {
	ID            string            `yaml:"id"`
	ApiMethod     string            `yaml:"msf-method"`
	ModuleType    string            `yaml:"msf-type"`
	ModuleName    string            `yaml:"msf-name"`
	MethodOptions map[string]string `yaml:"msf-options"`
	client        *rpc.Metasploit
	options       *protocols.ExecuterOptions
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators
}

// Testing
var (
	user = "fprime"
	host = "http://192.168.1.130:55552"
	pass = "password"
)

func (r *Request) GetID() string {
	return r.ID
}

func (r *Request) Requests() int {
	return 1
}

func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	if r.client == nil {
		newClient, err := rpc.New(host, user, pass)
		if err != nil {
			return errors.Wrap(err, "Unable to create Metasploit RPC API client")
		}
		r.client = newClient
	}
	r.options = options
	moduleOptions, err := r.client.ModuleOptions(r.ModuleType, r.ModuleName)
	if err != nil {
		return errors.Wrap(err, "Error getting module options")
	}

	for option, obj := range moduleOptions {
		if obj.Required && obj.Default == nil && r.MethodOptions[option] == "" {
			return errors.Errorf("Required option is not included in template %s", option)
		}
	}
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}
	return nil
}
