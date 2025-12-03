package logger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/ChristopherHX/github-act-runner/protocol/results"
)

const (
	// Websocket connection timeouts
	websocketDialTimeout    = 5 * time.Minute // Connection establishment timeout
	websocketMessageTimeout = 5 * time.Second // Individual message timeout
	websocketPingSize       = 64              // bytes
	// Results upload timeout
	resultsUploadTimeout = 5 * time.Minute
)

type LiveLogger interface {
	io.Closer
	SendLog(lines *protocol.TimelineRecordFeedLinesWrapper) error
}

type VssLiveLogger struct {
	JobRequest *protocol.AgentJobRequestMessage
	Connection *protocol.VssConnection
}

func (*VssLiveLogger) Close() error {
	return nil
}

func (logger *VssLiveLogger) SendLog(wrapper *protocol.TimelineRecordFeedLinesWrapper) error {
	return logger.Connection.SendLogLines(logger.JobRequest.Plan, logger.JobRequest.Timeline.ID, wrapper)
}

type WebsocketLivelogger struct {
	JobRequest    *protocol.AgentJobRequestMessage
	Connection    *protocol.VssConnection
	ws            *websocket.Conn
	FeedStreamURL string
}

func (logger *WebsocketLivelogger) Close() error {
	if logger.ws != nil {
		err := logger.ws.Close(websocket.StatusGoingAway, "Bye!")
		logger.ws = nil
		return err
	}
	return nil
}

func (logger *WebsocketLivelogger) Connect() error {
	err := logger.Close()
	if err != nil && logger.Connection.Trace {
		fmt.Printf("Failed to close old websocket connection %s\n", err.Error())
	}
	if logger.Connection.Trace {
		fmt.Printf("Try to connect to websocket %s\n", logger.FeedStreamURL)
	}
	re := regexp.MustCompile("(?i)^http(s?)://")
	feedStreamURL, err := url.Parse(re.ReplaceAllString(logger.FeedStreamURL, "ws$1://"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), websocketDialTimeout)
	defer cancel()
	//nolint:bodyclose // websocket.Dial doesn't return an HTTP response body to close
	ws, _, err := websocket.Dial(ctx, feedStreamURL.String(), &websocket.DialOptions{
		HTTPClient: logger.Connection.HTTPClient(),
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + logger.Connection.Token},
			"User-Agent":    []string{"github-act-runner/1.0.0"},
		},
	})
	// While reconnecting never assign this to null
	if ws != nil {
		logger.ws = ws
	}
	return err
}

func (logger *WebsocketLivelogger) SendLog(lines *protocol.TimelineRecordFeedLinesWrapper) error {
	// Do not try to send if something is wrong
	if logger.ws == nil {
		return fmt.Errorf("missing websocket connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), websocketMessageTimeout)
	defer cancel()
	return wsjson.Write(ctx, logger.ws, lines)
}

type WebsocketLiveloggerWithFallback struct {
	JobRequest    *protocol.AgentJobRequestMessage
	Connection    *protocol.VssConnection
	currentLogger LiveLogger
	FeedStreamURL string
	ForceWebsock  bool
}

func (logger *WebsocketLiveloggerWithFallback) InitializeVssLogger() {
	_ = logger.Close() // Ignore error for cleanup
	logger.currentLogger = &VssLiveLogger{
		JobRequest: logger.JobRequest,
		Connection: logger.Connection,
	}
}

func (logger *WebsocketLiveloggerWithFallback) Initialize() {
	_ = logger.Close() // Ignore error for cleanup
	if logger.FeedStreamURL != "" {
		wslogger := &WebsocketLivelogger{
			JobRequest:    logger.JobRequest,
			Connection:    logger.Connection,
			FeedStreamURL: logger.FeedStreamURL,
		}
		err := wslogger.Connect()
		if err == nil {
			logger.currentLogger = wslogger
			return
		} else if logger.Connection.Trace {
			fmt.Printf("Failed to connect to websocket %s, fallback to vsslogger\n", err.Error())
		}
	}
	if !logger.ForceWebsock {
		logger.InitializeVssLogger()
	}
}

func (logger *WebsocketLiveloggerWithFallback) Close() error {
	if logger.currentLogger != nil {
		err := logger.currentLogger.Close()
		logger.currentLogger = nil
		return err
	}
	return nil
}

func (logger *WebsocketLiveloggerWithFallback) SendLog(wrapper *protocol.TimelineRecordFeedLinesWrapper) error {
	if logger.currentLogger == nil {
		logger.Initialize()
	}
	err := logger.currentLogger.SendLog(wrapper)
	if err != nil {
		if logger.Connection.Trace {
			fmt.Printf("Failed to send webconsole log %s\n", err.Error())
		}
		if wslogger, err := logger.currentLogger.(*WebsocketLivelogger); err {
			if err := wslogger.Connect(); err != nil {
				if !logger.ForceWebsock {
					if logger.Connection.Trace {
						fmt.Printf("Failed to reconnect to websocket %s, fallback to vsslogger\n", err.Error())
					}
					logger.InitializeVssLogger()
					return logger.currentLogger.SendLog(wrapper)
				}
				return err
			}
			err := logger.currentLogger.SendLog(wrapper)
			if err != nil {
				if !logger.ForceWebsock {
					if logger.Connection.Trace {
						fmt.Printf("Failed to send webconsole log %s, fallback to vsslogger\n", err.Error())
					}
					logger.InitializeVssLogger()
					return logger.currentLogger.SendLog(wrapper)
				}
				return err
			}
			return nil
		}
	}
	return err
}

type BufferedLiveLogger struct {
	LiveLogger
	logchan     chan *protocol.TimelineRecordFeedLinesWrapper
	logfinished chan struct{} 
}

func (logger *BufferedLiveLogger) sendLogs(logchan chan *protocol.TimelineRecordFeedLinesWrapper, logfinished chan struct{}) {
	defer close(logfinished)
	for {
		lines, ok := <-logchan
		if !ok {
			return
		}
		st := time.Now()
		lp := st
		logsexit := false
		for {
			b := false
			div := lp.Sub(st)
			if div > time.Second {
				break
			}
			select {
			case line, ok := <-logchan:
				if ok {
					if line.StepID == lines.StepID {
						lines.Count += line.Count
						lines.Value = append(lines.Value, line.Value...)
					} else {
						_ = logger.LiveLogger.SendLog(lines)
						lines = line
						st = time.Now()
					}
				} else {
					b = true
				}
			case <-time.After(time.Second - div):
				b = true
			}
			if b {
				break
			}
			lp = time.Now()
		}
		_ = logger.LiveLogger.SendLog(lines)
		if logsexit {
			return
		}
	}
}

func (logger *BufferedLiveLogger) Close() error {
	if logger.logchan != nil {
		close(logger.logchan)
		logger.logchan = nil
		<-logger.logfinished
	}
	return nil
}

func (logger *BufferedLiveLogger) SendLog(wrapper *protocol.TimelineRecordFeedLinesWrapper) error {
	if logger.logchan == nil {
		logchan := make(chan *protocol.TimelineRecordFeedLinesWrapper, websocketPingSize)
		logger.logchan = logchan
		logfinished := make(chan struct{})
		logger.logfinished = logfinished
		go logger.sendLogs(logchan, logfinished)
	}
	logger.logchan <- wrapper
	return nil
}

type JobLogger struct {
	JobRequest           *protocol.AgentJobRequestMessage
	Connection           *protocol.VssConnection
	ResultsConnection    *protocol.VssConnection
	TimelineRecords      *protocol.TimelineRecordWrapper
	CurrentRecord        int64
	CurrentLine          int64
	JobBuffer            bytes.Buffer
	CurrentBuffer        bytes.Buffer
	ResultsJobBuffer     bytes.Buffer
	ResultsCurrentBuffer bytes.Buffer
	linefeedregex        *regexp.Regexp
	Logger               LiveLogger
	lineBuffer           []byte
	IsResults            bool
	ChangeID             int64
	CurrentJobLine       int64
	FirstBlock           bool
	FirstJobBlock        bool
	linesync             sync.Mutex
	loggersync           sync.Mutex
}

func (logger *JobLogger) Write(p []byte) (n int, err error) {
	logger.linesync.Lock()
	defer logger.linesync.Unlock()
	logger.lineBuffer = append(logger.lineBuffer, p...)
	if i := bytes.LastIndexByte(logger.lineBuffer, byte('\n')); i != -1 {
		logger.Log(string(logger.lineBuffer[:i]))
		logger.lineBuffer = logger.lineBuffer[i+1:]
	}
	return len(p), nil
}

func (logger *JobLogger) current() *protocol.TimelineRecord {
	if logger.CurrentRecord < logger.TimelineRecords.Count {
		return logger.TimelineRecords.Value[logger.CurrentRecord]
	}
	return nil
}

func (logger *JobLogger) Current() *protocol.TimelineRecord {
	logger.loggersync.Lock()
	defer logger.loggersync.Unlock()
	return logger.current()
}

func (logger *JobLogger) MoveNext() *protocol.TimelineRecord {
	return logger.MoveNextExt(true)
}

func (logger *JobLogger) MoveNextExt(startNextRecord bool) *protocol.TimelineRecord {
	logger.loggersync.Lock()
	defer logger.loggersync.Unlock()
	cur := logger.current()
	if cur == nil {
		return nil
	}
	logger.uploadBlock(cur, true)
	logger.CurrentRecord++
	logger.CurrentBuffer.Reset()
	logger.ResultsCurrentBuffer.Reset()
	logger.CurrentLine = 0
	if c := logger.current(); c != nil && startNextRecord {
		c.Start()
		return c
	}
	_ = logger.update()
	return nil
}

func (logger *JobLogger) uploadBlock(cur *protocol.TimelineRecord, finalBlock bool) {
	if !logger.IsResults && finalBlock && logger.CurrentBuffer.Len() > 0 {
		logid, err := logger.Connection.UploadLogFile(
			logger.JobRequest.Timeline.ID,
			logger.JobRequest,
			logger.CurrentBuffer.String(),
		)
		if err == nil {
			cur.Log = &protocol.TaskLogReference{ID: logid}
		}
	}
	if logger.ResultsConnection != nil && (finalBlock || logger.ResultsCurrentBuffer.Len() > 2*1024*1024) {
		rs := &results.ResultsService{
			Connection: logger.ResultsConnection,
		}
		ctx, cancel := context.WithTimeout(context.Background(), resultsUploadTimeout)
		defer cancel()
		_ = rs.UploadResultsStepLogAsync(ctx, logger.JobRequest.Plan.PlanID, logger.JobRequest.JobID, cur.ID,
			&logger.ResultsCurrentBuffer, int64(logger.ResultsCurrentBuffer.Len()), logger.FirstBlock, finalBlock,
			logger.CurrentLine) // Ignore upload error for async operation
		logger.FirstBlock = false
		logger.ResultsCurrentBuffer.Reset()
	}
}

func (logger *JobLogger) Finish() {
	logger.loggersync.Lock()
	defer logger.loggersync.Unlock()
	logger.uploadJobBlob(true)
}

func (logger *JobLogger) uploadJobBlob(finalBlock bool) {
	if !logger.IsResults && finalBlock && logger.JobBuffer.Len() > 0 && len(logger.TimelineRecords.Value) > 0 {
		logid, err := logger.Connection.UploadLogFile(
			logger.JobRequest.Timeline.ID,
			logger.JobRequest,
			logger.JobBuffer.String(),
		)
		if err == nil {
			logger.TimelineRecords.Value[0].Log = &protocol.TaskLogReference{ID: logid}
			_ = logger.update()
		}
	}
	if logger.ResultsConnection != nil && (finalBlock || logger.ResultsJobBuffer.Len() > 2*1024*1024) {
		if logger.ResultsConnection != nil {
			rs := &results.ResultsService{
				Connection: logger.ResultsConnection,
			}
			ctx, cancel := context.WithTimeout(context.Background(), resultsUploadTimeout)
			defer cancel()
			_ = rs.UploadResultsJobLogAsync(ctx, logger.JobRequest.Plan.PlanID, logger.JobRequest.JobID,
				&logger.ResultsJobBuffer, int64(logger.ResultsJobBuffer.Len()), logger.FirstJobBlock, finalBlock,
				logger.CurrentJobLine) // Ignore upload error for async operation
			logger.FirstJobBlock = false
			logger.ResultsJobBuffer.Reset()
		}
	}
}

func (logger *JobLogger) Update() error {
	logger.loggersync.Lock()
	defer logger.loggersync.Unlock()
	return logger.update()
}

func (logger *JobLogger) update() error {
	var errResults, errVss error
	if logger.ResultsConnection != nil {
		logger.ChangeID++
		updatereq := &results.StepsUpdateRequest{}
		updatereq.ChangeOrder = logger.ChangeID
		updatereq.WorkflowRunBackendID = logger.JobRequest.Plan.PlanID
		updatereq.WorkflowJobRunBackendID = logger.TimelineRecords.Value[0].ID
		updatereq.Steps = make([]results.Step, len(logger.TimelineRecords.Value)-1)
		for i, rec := range logger.TimelineRecords.Value[1:] {
			updatereq.Steps[i] = results.ConvertTimelineRecordToStep(rec)
		}
		rs := &results.ResultsService{
			Connection: logger.ResultsConnection,
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		errResults = rs.UpdateWorkflowStepsAsync(ctx, updatereq)
	}

	if !logger.IsResults {
		errVss = logger.Connection.UpdateTimeLine(logger.JobRequest.Timeline.ID, logger.JobRequest, logger.TimelineRecords)
	}
	return errors.Join(errResults, errVss)
}

func (logger *JobLogger) Append(record *protocol.TimelineRecord) *protocol.TimelineRecord {
	logger.loggersync.Lock()
	defer logger.loggersync.Unlock()
	if l := len(logger.TimelineRecords.Value); l > 0 {
		record.Order = logger.TimelineRecords.Value[l-1].Order + 1
	}
	logger.TimelineRecords.Value = append(logger.TimelineRecords.Value, record)
	logger.TimelineRecords.Count = int64(len(logger.TimelineRecords.Value))
	return record
}

func (logger *JobLogger) Insert(record *protocol.TimelineRecord) *protocol.TimelineRecord {
	logger.loggersync.Lock()
	defer logger.loggersync.Unlock()
	x := append(make([]*protocol.TimelineRecord, 0), logger.TimelineRecords.Value[:logger.CurrentRecord]...)
	x = append(x, record)
	logger.TimelineRecords.Value = append(x, logger.TimelineRecords.Value[logger.CurrentRecord:]...)
	logger.TimelineRecords.Count = int64(len(logger.TimelineRecords.Value))
	return record
}

func (logger *JobLogger) Log(lines string) {
	logger.loggersync.Lock()
	defer logger.loggersync.Unlock()
	if logger.linefeedregex == nil {
		logger.linefeedregex = regexp.MustCompile(`(\r\n|\r|\n)`)
	}
	if logger.CurrentLine == 0 {
		logger.CurrentLine = 1
		logger.FirstBlock = true
		logger.FirstJobBlock = true
	}
	lines = logger.linefeedregex.ReplaceAllString(strings.TrimSuffix(lines, "\r\n"), "\n")
	if !logger.IsResults {
		_, _ = logger.JobBuffer.WriteString(lines + "\n")
	}
	if logger.ResultsConnection != nil {
		_, _ = logger.ResultsJobBuffer.WriteString(lines + "\n")
	}
	cur := logger.current()
	if cur == nil {
		return
	}
	if !logger.IsResults {
		_, _ = logger.CurrentBuffer.WriteString(lines + "\n")
	}
	if logger.ResultsConnection != nil {
		_, _ = logger.ResultsCurrentBuffer.WriteString(lines + "\n")
	}
	cline := logger.CurrentLine
	wrapper := &protocol.TimelineRecordFeedLinesWrapper{
		StartLine: &cline,
		Value:     strings.Split(lines, "\n"),
		StepID:    cur.ID,
	}
	wrapper.Count = int64(len(wrapper.Value))
	logger.CurrentLine += wrapper.Count
	logger.CurrentJobLine += wrapper.Count
	timeline := regexp.MustCompile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z ")
	length := len("2021-04-02T15:50:14.6619714Z ")
	for i := 0; i < len(wrapper.Value); i++ {
		if timeline.MatchString(wrapper.Value[i]) {
			wrapper.Value[i] = wrapper.Value[i][length:]
		}
	}
	_ = logger.Logger.SendLog(wrapper) // Ignore send error for logging
	logger.uploadBlock(cur, false)
	logger.uploadJobBlob(false)
}
