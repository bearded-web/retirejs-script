package retirejs

import (
	"encoding/json"
	"fmt"

	"code.google.com/p/go.net/context"
	"github.com/facebookgo/stackerr"

	"github.com/bearded-web/bearded/models/plugin"
	"github.com/bearded-web/bearded/models/report"
	"github.com/bearded-web/bearded/models/tech"
	"github.com/bearded-web/bearded/pkg/script"
	"github.com/davecgh/go-spew/spew"
)

const toolName = "barbudo/retirejs"

//var supportedVersions = []string{
//	"0.0.2",
//}

type RetireJsItem struct {
	Component       string   `json:"component"`
	Version         string   `json:"version"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
}

type RetireJs struct {
}

func New() *RetireJs {
	return &RetireJs{}
}

func (s *RetireJs) Handle(ctx context.Context, client script.ClientV1, conf *plugin.Conf) error {
	// Check if retirejs plugin is available
	println("get tool")
	pl, err := s.getTool(ctx, client)
	if err != nil {
		return err
	}

	println("run retirejs")
	// Run retirejs util
	rep, err := pl.Run(ctx, pl.LatestVersion(), &plugin.Conf{CommandArgs: conf.Target})
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
	issues := []*report.Issue{}
	techs := []*report.Tech{}

	url := conf.Target
	for _, item := range items {
		if item.Component != "" {
			t := report.Tech{
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
		issue := report.Issue{
			Summary:  fmt.Sprintf("Vulnerability in %s version %s", item.Component, item.Version),
			Severity: report.SeverityMedium,
			Urls:     []*report.Url{&report.Url{Url: url}},
		}
		for _, vuln := range item.Vulnerabilities {
			issue.Extras = append(issue.Extras, &report.Extra{Url: vuln})
		}
		issues = append(issues, &issue)
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

func (s *RetireJs) parseWappalyzer(str string) []*report.Tech {
	ts := []*report.Tech{}
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
