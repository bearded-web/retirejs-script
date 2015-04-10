package retirejs

import (
	"encoding/json"
	"fmt"

	"code.google.com/p/go.net/context"
	"github.com/davecgh/go-spew/spew"
	"github.com/facebookgo/stackerr"

	"github.com/bearded-web/bearded/models/issue"
	"github.com/bearded-web/bearded/models/plan"
	"github.com/bearded-web/bearded/models/report"
	"github.com/bearded-web/bearded/models/tech"
	"github.com/bearded-web/bearded/pkg/script"
	"strings"
)

const toolName = "barbudo/retirejs"

//var supportedVersions = []string{
//	"0.0.2",
//}

var SeverityMap = map[string]issue.Severity{
	"low":    issue.SeverityLow,
	"medium": issue.SeverityMedium,
	"high":   issue.SeverityHigh,
}

type Identifiers struct {
	Summary MultiLine `json:"summary"`
	Bug     string    `json:"bug"`
	Release string    `json:"release"`
	Commit  string    `json:"commit"`
}

type Vulnerability struct {
	Severity    string       `json:"serverity"`
	Info        []string     `json:"info"`
	Identifiers *Identifiers `json:"identifiers"`
}

type RetireJsItem struct {
	Component       string           `json:"component"`
	Version         string           `json:"version"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities,omitempty"`
}

type RetireJs struct{}

func New() *RetireJs {
	return &RetireJs{}
}

func (s *RetireJs) Handle(ctx context.Context, client script.ClientV1, conf *plan.Conf) error {
	// Check if retirejs plugin is available
	println("get tool")
	pl, err := s.getTool(ctx, client)
	if err != nil {
		return err
	}

	println("run retirejs")
	// Run retirejs util
	rep, err := pl.Run(ctx, pl.LatestVersion(), &plan.Conf{CommandArgs: conf.Target})
	if err != nil {
		return stackerr.Wrap(err)
	}
	println("retirejs finished")
	// Get and parse retirejs output
	if rep.Type != report.TypeRaw {
		return stackerr.Newf("Retirejs report type should be TypeRaw, but got %s instead", rep.Type)
	}
	items := map[string]*RetireJsItem{}
	err = json.Unmarshal([]byte(rep.Raw.Raw), &items)
	if err != nil {
		return stackerr.Wrap(err)
	}
	multiReport := report.Report{
		Type:  report.TypeMulti,
		Multi: []*report.Report{},
	}

	// Create issue report, based on retirejs vulnerabilities
	// Create tech report, based on retirejs disclosures
	issues := []*issue.Issue{}
	techs := []*tech.Tech{}

	for _, item := range items {
		if item.Component != "" {
			t := tech.Tech{
				Name:       item.Component,
				Version:    item.Version,
				Confidence: 100,
				Categories: []tech.Category{tech.JavascriptFrameworks},
			}
			techs = append(techs, &t)
		}
		if item.Vulnerabilities == nil || len(item.Vulnerabilities) == 0 {
			continue
		}

		for _, vuln := range item.Vulnerabilities {
			issueObj := issue.Issue{
				Summary:  fmt.Sprintf("Vulnerability in %s version %s", item.Component, item.Version),
				Severity: issue.SeverityMedium,
			}
			if severity, ok := SeverityMap[vuln.Severity]; ok {
				issueObj.Severity = severity
			}
			for _, info := range vuln.Info {
				issueObj.References = append(issueObj.References, &issue.Reference{Url: info})
			}
			desc := []string{}
			if len(vuln.Identifiers.Summary) > 0 {
				desc = append(desc, vuln.Identifiers.Summary.String())
			}
			if len(vuln.Identifiers.Commit) > 0 {
				desc = append(desc, fmt.Sprintf("Fixed in '%s' commit", vuln.Identifiers.Commit))
			}
			if len(vuln.Identifiers.Release) > 0 {
				desc = append(desc, fmt.Sprintf("Fixed in '%s' release", vuln.Identifiers.Release))
			}
			if len(desc) > 0 {
				issueObj.Desc = strings.Join(desc, "\n")
			}
			issues = append(issues, &issueObj)
		}
	}
	//	techs = s.parseWappalyzer(wapp)
	if len(issues) > 0 {
		issueReport := report.Report{
			Type:   report.TypeIssues,
			Issues: issues,
		}
		multiReport.Multi = append(multiReport.Multi, &issueReport)
	}
	if len(techs) > 0 {
		techReport := report.Report{
			Type:  report.TypeTechs,
			Techs: techs,
		}
		multiReport.Multi = append(multiReport.Multi, &techReport)
	}
	if len(multiReport.Multi) == 0 {
		multiReport = report.Report{Type: report.TypeEmpty}
	}
	println("send report")
	// push reports
	client.SendReport(ctx, &multiReport)
	spew.Dump(multiReport)
	println("sent")
	// exit
	return nil
}

func (s *RetireJs) parseWappalyzer(str string) []*tech.Tech {
	ts := []*tech.Tech{}
	err := json.Unmarshal([]byte(str), &ts)
	if err != nil {
		panic(err)
	}
	return ts
}

// Check if retirejs plugin is available
func (s *RetireJs) getTool(ctx context.Context, client script.ClientV1) (*script.Plugin, error) {
	pl, err := client.GetPlugin(ctx, toolName)
	if err != nil {
		return nil, err
	}
	return pl, err
	//	pl.LatestSupportedVersion(supportedVersions)
}
