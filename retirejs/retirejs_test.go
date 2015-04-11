package retirejs

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"testing"
	"time"

	"golang.org/x/net/context"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/bearded-web/bearded/models/plan"
	"github.com/bearded-web/bearded/models/report"
	"github.com/bearded-web/bearded/pkg/script"
)

type ClientMock struct {
	mock.Mock
	*script.FakeClient
}

func (m *ClientMock) GetPlugin(ctx context.Context, name string) (*script.Plugin, error) {
	return script.NewPlugin(name, m, "0.0.2"), nil
}

func (m *ClientMock) RunPlugin(ctx context.Context, conf *plan.WorkflowStep) (*report.Report, error) {
	args := m.Called(ctx, conf)
	return args.Get(0).(*report.Report), args.Error(1)
}

func (m *ClientMock) SendReport(ctx context.Context, rep *report.Report) error {
	data, _ := json.Marshal(rep)
	println(string(data))
	args := m.Called(ctx, rep)
	return args.Error(0)
}

func TestHandle(t *testing.T) {
	target := "http://example.com"
	bg := context.Background()
	testData := []struct {
		ToolReport     string
		ExpectedReport *report.Report
	}{
		{loadTestData("tool-report1.json"), loadReport("report1.json")},
		{loadTestData("tool-report-empty.json"), loadReport("report-empty.json")},
	}

	for _, data := range testData {
		client := &ClientMock{}
		pl := plan.WorkflowStep{
			Name:   "underscan",
			Plugin: "barbudo/retirejs:0.0.2",
			Conf:   &plan.Conf{CommandArgs: fmt.Sprintf(target)},
		}
		client.On("RunPlugin", bg, &pl).
			Return(&report.Report{Type: report.TypeRaw, Raw: report.Raw{Raw: data.ToolReport}}, nil).Once()
		client.On("SendReport", bg, data.ExpectedReport).Return(nil).Once()

		var s script.Scripter = New()
		err := s.Handle(bg, client, &plan.Conf{Target: target})
		require.NoError(t, err)
		client.Mock.AssertExpectations(t)
	}
}

func TestCheckPlugin(t *testing.T) {
	bg := context.Background()
	client := &ClientMock{}

	retire := New()
	ctx, _ := context.WithTimeout(bg, 1*time.Second)
	retire.getTool(ctx, client)
}

// test data
const testDataDir = "test_data"

func loadTestData(filename string) string {
	file := path.Join(testDataDir, filename)
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func loadReport(filename string) *report.Report {
	rep := report.Report{}
	if err := json.Unmarshal([]byte(loadTestData(filename)), &rep); err != nil {
		panic(err)
	}
	return &rep
}
