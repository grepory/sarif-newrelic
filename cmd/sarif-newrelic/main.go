package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/securego/gosec/v2/report/sarif"
)

const EventType = "VulnerabilityScanEvent"

type reportShell struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
}

var fname = flag.String("f", "in.sarif", "Path to SARIF report")
var nrLicenseKey = flag.String("k", "", "NR License Key")

func main() {
	flag.Parse()

	if *nrLicenseKey == "" {
		log.Fatal("must specify license key with -k")
	}

	sarifIn, err := os.ReadFile(*fname)
	if err != nil {
		log.Fatal(err)
	}

	shell := reportShell{}

	if err := json.Unmarshal(sarifIn, &shell); err != nil {
		log.Fatal(err)
	}

	report := sarif.NewReport(shell.Version, shell.Schema)

	if err := json.Unmarshal(sarifIn, &report); err != nil {
		log.Fatal(err)
	}

	app, err := newrelic.NewApplication(
		newrelic.ConfigAppName("sarif-newrelic"),
		newrelic.ConfigLicense(*nrLicenseKey),
		newrelic.ConfigDebugLogger(os.Stdout),
	)

	if err != nil {
		log.Fatal(err)
	}

	if err := app.WaitForConnection(30 * time.Second); err != nil {
		log.Fatal(err)
	}

	for _, run := range report.Runs {
		tool := run.Tool.Driver.Name
		toolVersion := run.Tool.Driver.Version
		rules := run.Tool.Driver.Rules

		for _, result := range run.Results {
			event := map[string]interface{}{}
			event["tool"] = tool
			event["toolVersion"] = toolVersion
			event["ruleId"] = result.RuleID
			event["message"] = result.Message.Text
			event["fullDescription"] = rules[result.RuleIndex].FullDescription.Text
			event["helpUri"] = rules[result.RuleIndex].FullDescription.Text
			event["helpText"] = rules[result.RuleIndex].Help.Text

			for _, location := range result.Locations {
				// For now, we're targeting things to do with containers.
				// In this case, location.physicalLocation.artifactLocation.uri should contain
				// the container image name.
				event["location"] = location.PhysicalLocation.ArtifactLocation.URI

				fmt.Println("publishing event")
				app.RecordCustomEvent(EventType, event)
			}
		}
	}

	app.Shutdown(5 * time.Minute)
}
