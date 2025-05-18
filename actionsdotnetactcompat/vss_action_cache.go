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
	"github.com/actions-oss/act-cli/pkg/runner"
	"github.com/google/uuid"
)

type VssActionCache struct {
	VssConnection *protocol.VssConnection
	Plan          *protocol.TaskOrchestrationPlanReference
	GHToken       string
	HttpClient    *http.Client

	mapping map[string]string
	delete  []string
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
		if len(resolvedSha) == len("0000000000000000000000000000000000000000") {
			resolvedSha = uuid.NewString()
			shouldDelete = true
		}

		targetFile, err := fetchAction(ctx, cacheDir, actionurl[0], actionurl[1], resolvedSha, v.TarballUrl, token, cache.HttpClient)
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
func (cache *VssActionCache) GetTarArchive(ctx context.Context, cacheDir string, sha string, includePrefix string) (io.ReadCloser, error) {
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

var _ runner.ActionCache = (*VssActionCache)(nil)
