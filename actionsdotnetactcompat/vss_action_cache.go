package actionsdotnetactcompat

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
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
	CacheDir      string

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
		if len(resolvedSha) != len("0000000000000000000000000000000000000000") {
			resolvedSha = uuid.NewString()
			shouldDelete = true
		}

		targetFile, err := fetchAction(ctx, cache.CacheDir, actionurl[0], actionurl[1], resolvedSha, v.TarballUrl, token, cache.HttpClient)
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
	cleanIncludePrefix := path.Clean(includePrefix)
	go func() {
		defer pr.Close()
		writer := tar.NewWriter(pw)
		defer writer.Close()
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
		treader := tar.NewReader(gzr)
		for {
			header, err := treader.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				_ = pw.CloseWithError(err)
				return
			}
			name := header.Name
			idx := strings.Index(name, "/")
			if idx == -1 {
				continue
			}
			name = name[idx+1:]
			if strings.HasPrefix(name, cleanIncludePrefix+"/") {
				name = name[len(cleanIncludePrefix)+1:]
			} else if cleanIncludePrefix != "." && name != cleanIncludePrefix {
				continue
			}
			header.Name = name
			err = writer.WriteHeader(header)
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			_, err = io.Copy(writer, treader)
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
		}
	}()
	return pr, nil
}

var _ runner.ActionCache = (*VssActionCache)(nil)
