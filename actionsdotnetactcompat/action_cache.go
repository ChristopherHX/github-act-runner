package actionsdotnetactcompat

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

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
