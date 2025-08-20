package actionsdotnetactcompat

import (
	"context"
	"fmt"
	"strings"

	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/actions-oss/act-cli/pkg/runner"
	"github.com/google/uuid"
)

type VssActionCache struct {
	ActionCacheBase
}

// Fetch implements runner.ActionCache.
func (cache *VssActionCache) Fetch(ctx context.Context, cacheDir string, url string, ref string, token string) (string, error) {
	actionList := &protocol.ActionReferenceList{}
	actionurl := strings.Split(url, "/")
	actionurl = actionurl[len(actionurl)-2:]
	actionList.Actions = []protocol.ActionReference{
		{NameWithOwner: strings.Join(actionurl, "/"), Ref: ref},
	}
	actionDownloadInfo := &protocol.ActionDownloadInfoCollection{}
	err := cache.VssConnection.RequestWithContext(ctx, "27d7f831-88c1-4719-8ca1-6a061dad90eb", "6.0-preview", "POST", map[string]string{
		"scopeIdentifier": cache.Plan.ScopeIdentifier,
		"hubName":         cache.Plan.PlanType,
		"planId":          cache.Plan.PlanID,
	}, nil, actionList, actionDownloadInfo)
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
		if len(resolvedSha) != len("0000000000000000000000000000000000000000") {
			resolvedSha = uuid.NewString()
			shouldDelete = true
		}

		targetFile, err := fetchAction(ctx, cache.CacheDir, actionurl[0], actionurl[1], resolvedSha, v.TarballURL, token, cache.HttpClient)
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

var _ runner.ActionCache = (*VssActionCache)(nil)
