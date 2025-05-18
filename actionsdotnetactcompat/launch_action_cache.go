package actionsdotnetactcompat

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/ChristopherHX/github-act-runner/protocol/launch"
	"github.com/actions-oss/act-cli/pkg/runner"
	"github.com/google/uuid"
)

type LaunchActionCache struct {
	VssConnection *protocol.VssConnection
	Plan          *protocol.TaskOrchestrationPlanReference
	GHToken       string
	HttpClient    *http.Client

	mapping        map[string]string
	delete         []string
	LaunchEndpoint string
	JobID          string
}

// Fetch implements runner.ActionCache.
func (cache *LaunchActionCache) Fetch(ctx context.Context, cacheDir string, url string, ref string, token string) (string, error) {
	actionList := &launch.ActionReferenceRequestList{}
	actionurl := strings.Split(url, "/")
	actionurl = actionurl[len(actionurl)-2:]
	actionList.Actions = []launch.ActionReferenceRequest{
		{Action: strings.Join(actionurl, "/"), Version: ref},
	}
	actionDownloadInfo := &launch.ActionDownloadInfoResponseCollection{}
	urlBuilder := protocol.VssConnection{TenantURL: cache.LaunchEndpoint}
	url, err := urlBuilder.BuildURL("actions/build/{planId}/jobs/{jobId}/runnerresolve/actions", map[string]string{
		"jobId":  cache.JobID,
		"planId": cache.Plan.PlanID,
	}, nil)
	if err != nil {
		return "", err
	}
	err = cache.VssConnection.RequestWithContext2(ctx, "POST", url, "", actionList, actionDownloadInfo)
	if err != nil {
		return "", err
	}

	for _, v := range actionDownloadInfo.Actions {
		token := cache.GHToken
		if v.Authentication != nil && v.Authentication.Token != "" {
			token = v.Authentication.Token
		}
		resolvedSha := v.ResolvedSha
		var shouldDelete bool
		if len(resolvedSha) == len("0000000000000000000000000000000000000000") {
			resolvedSha = uuid.NewString()
			shouldDelete = true
		}

		targetFile, err := fetchAction(ctx, cacheDir, actionurl[0], actionurl[1], resolvedSha, v.TarUrl, token, cache.HttpClient)
		if err != nil {
			return "", err
		}
		if cache.mapping == nil {
			cache.mapping = make(map[string]string)
		}
		if shouldDelete {
			cache.delete = append(cache.delete, targetFile)
		}
		cache.mapping[cacheDir+"@"+resolvedSha] = targetFile
		return resolvedSha, nil
	}
	return "", fmt.Errorf("no action found for %s", url)
}

// GetTarArchive implements runner.ActionCache.
func (cache *LaunchActionCache) GetTarArchive(ctx context.Context, cacheDir string, sha string, includePrefix string) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	go func() {
		defer pr.Close()
		reader, err := os.Open(cache.mapping[cacheDir+"@"+sha])
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		defer reader.Close()
		gzr, err := gzip.NewReader(reader)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		defer gzr.Close()
		_, err = io.Copy(pw, gzr)
		if err != nil {
			_ = pw.CloseWithError(err)
		}
	}()
	return pr, nil
}

var _ runner.ActionCache = (*LaunchActionCache)(nil)
