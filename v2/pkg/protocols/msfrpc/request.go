package msfrpc

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

func (r *Request) ExecuteWithResults(input string, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// By this point, Compile would have failed, so we know the options are correct for the module we're executing
	if r.MethodOptions["RHOSTS"] == "{{Hostname}}" {
		rhost, err := url.Parse(input)
		if err != nil {
			return errors.Wrap(err, "Unable to parse input")
		}
		r.MethodOptions["RHOSTS"] = rhost.Hostname()
	}
	moduleExecRes, err := r.client.ModuleExecute(r.ModuleType, r.ModuleName, r.MethodOptions)
	if err != nil {
		return errors.Wrap(err, "Unable to execute module")
	}
	jobID := moduleExecRes.JobId
	gologger.Info().Msgf("Module launched, Job ID is %d", jobID)
	sessionOpen := false
	var sessionId uint32
	for !sessionOpen {
		sessionList, err := r.client.SessionList()
		if err != nil {
			return errors.Wrap(err, "Unable to get session list")
		}
		for id, info := range sessionList {
			if strings.Contains(info.ViaExploit, r.ModuleName) {
				// Probably find a better way to do this just in case, but it should at least be a shell from this template
				sessionOpen = true
				sessionId = id
				break
			}
		}
	}
	r.options.Progress.IncrementRequests()
	r.options.Output.Request(r.options.TemplateID, input, "msfrpc", err)
	gologger.Verbose().Msgf("SESSION CREATED: %d", sessionId)
	outputEvent := r.responseToDSLMap(input, input)
	outputEvent["ip"] = input
	for k, v := range previous {
		outputEvent[k] = v
	}
	// for k, v := range payloads {
	// 	outputEvent[k] = v
	// }
	// for k, v := range inputEvents {
	// 	outputEvent[k] = v
	// }
	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
	event.OperatorsResult.Matched = true
	event.Results = r.MakeResultEvent(event)
	// if r.CompiledOperators != nil {
	// 	result, ok := r.CompiledOperators.Execute(outputEvent, r.Match, r.Extract)
	// 	if ok && result != nil {
	// 		event.OperatorsResult = result
	// 		event.OperatorsResult.PayloadValues = payloads
	// 		event.Results = r.MakeResultEvent(event)
	// 	}
	// }
	callback(event)
	r.options.Progress.IncrementMatched()
	return nil
}
