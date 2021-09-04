package msfrpc

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

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
	g := r.options.Output.Colorizer().BrightRed("G").String()
	a := r.options.Output.Colorizer().BrightYellow("A").String()
	y := r.options.Output.Colorizer().BrightGreen("Y").String()
	b := r.options.Output.Colorizer().BrightBlue("B").String()
	o := r.options.Output.Colorizer().BrightMagenta("O").String()
	m := r.options.Output.Colorizer().BrightRed("M").String()
	ba := r.options.Output.Colorizer().BrightYellow("B").String()
	gayBombColor := fmt.Sprintf("%s%s%s %s%s%s%s", g, a, y, b, o, m, ba)
	gologger.Info().Msgf("%s launched, %s%s%s%s number is %d", gayBombColor, b, o, m, ba, jobID)
	sessionOpen := false
	jobDead := false
	type session struct {
		Type        string `msgpack:"type"`
		TunnelLocal string `msgpack:"tunnel_local"`
		TunnelPeer  string `msgpack:"tunnel_peer"`
		ViaExploit  string `msgpack:"via_exploit"`
		ViaPayload  string `msgpack:"via_payload"`
		Description string `msgpack:"desc"`
		Info        string `msgpack:"info"`
		Workspace   string `msgpack:"workspace"`
		SessionHost string `msgpack:"session_host"`
		SessionPort int    `msgpack:"session_port"`
		Username    string `msgpack:"username"`
		UUID        string `msgpack:"uuid"`
		ExploitUUID string `msgpack:"exploit_uuid"`
	}
	// go func() {
	var sessionObj session
	for !sessionOpen && !jobDead {
		sessionList, err := r.client.SessionList()
		if err != nil {
			log.Fatalln("Error getting session list")
		}
		jobList, err := r.client.JobList()
		if err != nil {
			log.Fatalln("Error getting job list")
		}
		for _, info := range sessionList {
			if strings.Contains(info.ViaExploit, r.ModuleName) {
				// Probably find a better way to do this just in case, but it should at least be a shell from this template
				sessionOpen = true
				sessionObj = info
				break
			}
			for _, job := range jobList {
				if strings.ToLower(job) == fmt.Sprintf("%s: %s", strings.ToLower(r.ModuleType), strings.ToLower(r.ModuleName)) {
					// Job is still running, let's continue the outer loop
					break
				} else {
					jobDead = true
					break
				}
			}
		}
		time.Sleep(time.Second * 1)
	}
	gologger.Info().Msgf("%s HIT ON: %s", gayBombColor, sessionObj.TunnelPeer)
	// }()
	r.options.Progress.IncrementRequests()
	r.options.Progress.IncrementMatched()
	r.options.Output.Request(r.options.TemplateID, input, "msfrpc", err)
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
	if r.CompiledOperators != nil {
		result, ok := r.CompiledOperators.Execute(outputEvent, r.Match, r.Extract)
		if ok && result != nil {
			event.OperatorsResult = result
			// event.OperatorsResult.PayloadValues = payloads
			event.Results = r.MakeResultEvent(event)
		}
	}
	// if r.CompiledOperators != nil {
	// 	result, ok := r.CompiledOperators.Execute(outputEvent, r.Match, r.Extract)
	// 	if ok && result != nil {
	// 		event.OperatorsResult = result
	// 		event.OperatorsResult.PayloadValues = payloads
	// 		event.Results = r.MakeResultEvent(event)
	// 	}
	// }
	callback(event)
	return nil
}
