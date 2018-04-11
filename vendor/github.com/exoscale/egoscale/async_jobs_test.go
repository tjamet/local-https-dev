package egoscale

import (
	"testing"
)

func TestAsyncJobs(t *testing.T) {
	var _ Command = (*QueryAsyncJobResult)(nil)
	var _ Command = (*ListAsyncJobs)(nil)
}

func TestQueryAsyncJobResult(t *testing.T) {
	req := &QueryAsyncJobResult{}
	if req.APIName() != "queryAsyncJobResult" {
		t.Errorf("API call doesn't match")
	}
	_ = req.response().(*QueryAsyncJobResultResponse)
}

func TestListAsyncJobs(t *testing.T) {
	req := &ListAsyncJobs{}
	if req.APIName() != "listAsyncJobs" {
		t.Errorf("API call doesn't match")
	}
	_ = req.response().(*ListAsyncJobsResponse)
}
