package logger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/ChristopherHX/github-act-runner/protocol/results"
	"golang.org/x/net/websocket"
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
	FeedStreamUrl string
}

func (logger *WebsocketLivelogger) Close() error {
	if logger.ws != nil {
		err := logger.ws.Close()
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
		fmt.Printf("Try to connect to websocket %s\n", logger.FeedStreamUrl)
	}
	origin, err := url.Parse(logger.Connection.TenantURL)
	if err != nil {
		return err
	}
	re := regexp.MustCompile("(?i)^http(s?)://")
	feedStreamUrl, err := url.Parse(re.ReplaceAllString(logger.FeedStreamUrl, "ws$1://"))
	if err != nil {
		return err
	}
	logger.ws, err = websocket.DialConfig(&websocket.Config{
		Location: feedStreamUrl,
		Origin:   origin,
		Version:  13,
		Header: http.Header{
			"Authorization": []string{"Bearer " + logger.Connection.Token},
		},
	})
	return err
}

func (logger *WebsocketLivelogger) SendLog(lines *protocol.TimelineRecordFeedLinesWrapper) error {
	return websocket.JSON.Send(logger.ws, lines)
}

type WebsocketLiveloggerWithFallback struct {
	JobRequest    *protocol.AgentJobRequestMessage
	Connection    *protocol.VssConnection
	currentLogger LiveLogger
	FeedStreamUrl string
	ForceWebsock  bool
}

func (logger *WebsocketLiveloggerWithFallback) InitializeVssLogger() {
	logger.Close()
	logger.currentLogger = &VssLiveLogger{
		JobRequest: logger.JobRequest,
		Connection: logger.Connection,
	}
}

func (logger *WebsocketLiveloggerWithFallback) Initialize() {
	logger.Close()
	if len(logger.FeedStreamUrl) > 0 {
		wslogger := &WebsocketLivelogger{
			JobRequest:    logger.JobRequest,
			Connection:    logger.Connection,
			FeedStreamUrl: logger.FeedStreamUrl,
		}
		err := wslogger.Connect()
		if err == nil {
			logger.currentLogger = wslogger
			return
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
		logchan := make(chan *protocol.TimelineRecordFeedLinesWrapper, 64)
		logger.logchan = logchan
		logfinished := make(chan struct{})
		logger.logfinished = logfinished
		go logger.sendLogs(logchan, logfinished)
	}
	logger.logchan <- wrapper
	return nil
}

type JobLogger struct {
	JobRequest      *protocol.AgentJobRequestMessage
	Connection      *protocol.VssConnection
	TimelineRecords *protocol.TimelineRecordWrapper
	CurrentRecord   int64
	CurrentLine     int64
	JobBuffer       bytes.Buffer
	CurrentBuffer   bytes.Buffer
	linefeedregex   *regexp.Regexp
	Logger          LiveLogger
	lineBuffer      []byte
	IsResults       bool
	ChangeId        int64
	CurrentJobLine  int64
	FirstBlock      bool
	FirstJobBlock   bool
}

func (logger *JobLogger) Write(p []byte) (n int, err error) {
	logger.lineBuffer = append(logger.lineBuffer, p...)
	if i := bytes.LastIndexByte(logger.lineBuffer, byte('\n')); i != -1 {
		logger.Log(string(logger.lineBuffer[:i]))
		logger.lineBuffer = logger.lineBuffer[i+1:]
	}
	return len(p), nil
}

func (logger *JobLogger) Current() *protocol.TimelineRecord {
	if logger.CurrentRecord < logger.TimelineRecords.Count {
		return logger.TimelineRecords.Value[logger.CurrentRecord]
	}
	return nil
}

func (logger *JobLogger) MoveNext() *protocol.TimelineRecord {
	return logger.MoveNextExt(true)
}

func (logger *JobLogger) MoveNextExt(startNextRecord bool) *protocol.TimelineRecord {
	cur := logger.Current()
	if cur == nil {
		return nil
	}
	logger.uploadBlock(cur, true)
	logger.CurrentRecord++
	logger.CurrentBuffer.Reset()
	if c := logger.Current(); c != nil && startNextRecord {
		c.Start()
		return c
	}
	_ = logger.Update()
	return nil
}

func (logger *JobLogger) uploadBlock(cur *protocol.TimelineRecord, finalBlock bool) {
	if finalBlock && logger.CurrentBuffer.Len() > 0 || logger.IsResults && (finalBlock || logger.CurrentBuffer.Len() > 2*1024*1024) {
		if logger.IsResults {
			rs := &results.ResultsService{
				Connection: logger.Connection,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			rs.UploadResultsStepLogAsync(ctx, logger.JobRequest.Plan.PlanID, logger.JobRequest.JobID, cur.ID, &logger.CurrentBuffer, int64(logger.CurrentBuffer.Len()), logger.FirstBlock, finalBlock, logger.CurrentLine)
			logger.FirstBlock = false
			logger.CurrentBuffer.Reset()
		} else if finalBlock {
			if logid, err := logger.Connection.UploadLogFile(logger.JobRequest.Timeline.ID, logger.JobRequest, logger.CurrentBuffer.String()); err == nil {
				cur.Log = &protocol.TaskLogReference{ID: logid}
			}
		}
	}
}

func (logger *JobLogger) Finish() {
	logger.uploadJobBlob(true)
}

func (logger *JobLogger) uploadJobBlob(finalBlock bool) {
	if (finalBlock && logger.JobBuffer.Len() > 0 || logger.IsResults && (finalBlock || logger.JobBuffer.Len() > 2*1024*1024)) && len(logger.TimelineRecords.Value) > 0 {
		if logger.IsResults {
			rs := &results.ResultsService{
				Connection: logger.Connection,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			rs.UploadResultsJobLogAsync(ctx, logger.JobRequest.Plan.PlanID, logger.JobRequest.JobID, &logger.JobBuffer, int64(logger.JobBuffer.Len()), logger.FirstJobBlock, finalBlock, logger.CurrentJobLine)
			logger.FirstJobBlock = false
			logger.JobBuffer.Reset()
		} else if finalBlock {
			if logid, err := logger.Connection.UploadLogFile(logger.JobRequest.Timeline.ID, logger.JobRequest, logger.JobBuffer.String()); err == nil {
				logger.TimelineRecords.Value[0].Log = &protocol.TaskLogReference{ID: logid}
				_ = logger.Update()
			}
		}
	}
}

func (logger *JobLogger) Update() error {
	if logger.IsResults {
		logger.ChangeId++
		updatereq := &results.StepsUpdateRequest{}
		updatereq.ChangeOrder = logger.ChangeId
		updatereq.WorkflowJobRunBackendID = logger.JobRequest.Plan.PlanID
		updatereq.WorkflowRunBackendID = logger.TimelineRecords.Value[0].ID
		updatereq.Steps = make([]results.Step, len(logger.TimelineRecords.Value)-1)
		for i, rec := range logger.TimelineRecords.Value[1:] {
			updatereq.Steps[i] = results.ConvertTimelineRecordToStep(*rec)
		}
		rs := &results.ResultsService{
			Connection: logger.Connection,
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return rs.UpdateWorkflowStepsAsync(ctx, updatereq)
	}
	return logger.Connection.UpdateTimeLine(logger.JobRequest.Timeline.ID, logger.JobRequest, logger.TimelineRecords)
}

func (logger *JobLogger) Append(record protocol.TimelineRecord) *protocol.TimelineRecord {
	if l := len(logger.TimelineRecords.Value); l > 0 {
		record.Order = logger.TimelineRecords.Value[l-1].Order + 1
	}
	logger.TimelineRecords.Value = append(logger.TimelineRecords.Value, &record)
	logger.TimelineRecords.Count = int64(len(logger.TimelineRecords.Value))
	return &record
}

func (logger *JobLogger) Insert(record protocol.TimelineRecord) *protocol.TimelineRecord {
	x := append(make([]*protocol.TimelineRecord, 0), logger.TimelineRecords.Value[:logger.CurrentRecord]...)
	y := append(x, &record)
	z := append(y, logger.TimelineRecords.Value[logger.CurrentRecord:]...)
	logger.TimelineRecords.Value = z
	logger.TimelineRecords.Count = int64(len(logger.TimelineRecords.Value))
	return &record
}

func (logger *JobLogger) Log(lines string) {
	if logger.linefeedregex == nil {
		logger.linefeedregex = regexp.MustCompile(`(\r\n|\r|\n)`)
	}
	if logger.CurrentLine == 0 {
		logger.CurrentLine = 1
		logger.FirstBlock = true
		logger.FirstJobBlock = true
	}
	lines = logger.linefeedregex.ReplaceAllString(strings.TrimSuffix(lines, "\r\n"), "\n")
	_, _ = logger.JobBuffer.WriteString(lines + "\n")
	cur := logger.Current()
	if cur == nil {
		return
	}
	_, _ = logger.CurrentBuffer.WriteString(lines + "\n")
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
	logger.Logger.SendLog(wrapper)
	logger.uploadBlock(cur, false)
	logger.uploadJobBlob(false)
}
