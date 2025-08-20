package actionsdotnetactcompat

import (
	"context"
	"fmt"
	"strings"

	"github.com/actions-oss/act-cli/pkg/runner"
	"github.com/google/uuid"

	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/ChristopherHX/github-act-runner/protocol/launch"
)

type LaunchActionCache struct {
	ActionCacheBase
	LaunchEndpoint string
	JobID          string
}

// Fetch implements runner.ActionCache.
func (cache *LaunchActionCache) Fetch(ctx context.Context, cacheDir, url, ref, token string) (string, error) {
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

	for _, v := range actionDownloadInfo.Actions { //nolint:dupl
		token := cache.GHToken
		if v.Authentication != nil && v.Authentication.Token != "" {
			token = v.Authentication.Token
		}
		resolvedSha := v.ResolvedSha
		var shouldDelete bool
		if len(resolvedSha) != len("0000000000000000000000000000000000000000") {
			resolvedSha = uuid.NewString()
			shouldDelete = true
		}

		targetFile, err := fetchAction(ctx, cache.CacheDir, actionurl[0], actionurl[1], resolvedSha, v.TarURL, token, cache.HttpClient)
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

var _ runner.ActionCache = (*LaunchActionCache)(nil)
