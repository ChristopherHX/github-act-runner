package actionsdotnetactcompat

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/actions-oss/act-cli/pkg/common"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

type ActionCacheBase struct {
	VssConnection *protocol.VssConnection
	Plan          *protocol.TaskOrchestrationPlanReference
	GHToken       string
	HttpClient    *http.Client
	CacheDir      string

	mapping map[string]string
	delete  []string
}

// GetTarArchive implements runner.ActionCache.
func (cache *ActionCacheBase) GetTarArchive(ctx context.Context, cacheDir string, sha string, includePrefix string) (io.ReadCloser, error) {
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

func fetchAction(ctx context.Context, target string, owner string, name string, resolvedSha string, tarURL string, token string, httpClient *http.Client) (targetFile string, reterr error) {
	logger := common.Logger(ctx)
	cachedTar := filepath.Join(target, owner+"."+name+"."+resolvedSha+".tar")
	defer func() {
		if reterr != nil {
			_ = os.Remove(cachedTar)
		}
	}()
	if fr, err := os.Open(cachedTar); err == nil {
		defer func() { _ = fr.Close() }()
		if logger != nil {
			logger.Infof("Found cache for action %v/%v (sha:%v) from %v", owner, name, resolvedSha, cachedTar)
		}
		return cachedTar, nil
	} else {
		if logger != nil {
			logger.Infof("Downloading action %v/%v (sha:%v) from %v", owner, name, resolvedSha, tarURL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarURL, http.NoBody)
		if err != nil {
			return "", err
		}
		if token != "" {
			req.Header.Add("Authorization", "token "+token)
		}
		req.Header.Add("User-Agent", "github-act-runner/1.0.0")
		req.Header.Add("Accept", "*/*")
		rsp, err := httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = rsp.Body.Close() }()
		if rsp.StatusCode != http.StatusOK {
			buf := &bytes.Buffer{}
			_, _ = io.Copy(buf, rsp.Body)
			return "", fmt.Errorf("failed to download action from %v response %v", tarURL, buf.String())
		}
		fo, err := os.Create(cachedTar)
		if err != nil {
			return "", err
		}
		defer func() { _ = fo.Close() }()
		len, err := io.Copy(fo, rsp.Body)
		if err != nil {
			return "", err
		}
		if rsp.ContentLength >= 0 && len != rsp.ContentLength {
			return "", fmt.Errorf("failed to download tar expected %v, but copied %v", rsp.ContentLength, len)
		}
	}
	return cachedTar, nil
}
