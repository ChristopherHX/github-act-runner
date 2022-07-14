package protocol

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

type LiveLogger interface {
	io.Closer
	SendLog(lines *TimelineRecordFeedLinesWrapper) error
}

type VssLiveLogger struct {
	JobRequest *AgentJobRequestMessage
	Connection *VssConnection
}

func (*VssLiveLogger) Close() error {
	return nil
}

func (logger *VssLiveLogger) SendLog(wrapper *TimelineRecordFeedLinesWrapper) error {
	return logger.Connection.SendLogLines(logger.JobRequest.Plan, logger.JobRequest.Timeline.ID, wrapper)
}

type WebsocketLivelogger struct {
	JobRequest    *AgentJobRequestMessage
	Connection    *VssConnection
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
	if err != nil {
		return err
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

func (logger *WebsocketLivelogger) SendLog(lines *TimelineRecordFeedLinesWrapper) error {
	return websocket.JSON.Send(logger.ws, lines)
}

type WebsocketLiveloggerWithFallback struct {
	JobRequest    *AgentJobRequestMessage
	Connection    *VssConnection
	currentLogger LiveLogger
	FeedStreamUrl string
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
	logger.InitializeVssLogger()
}

func (logger *WebsocketLiveloggerWithFallback) Close() error {
	if logger.currentLogger != nil {
		err := logger.currentLogger.Close()
		logger.currentLogger = nil
		return err
	}
	return nil
}

func (logger *WebsocketLiveloggerWithFallback) SendLog(wrapper *TimelineRecordFeedLinesWrapper) error {
	if logger.currentLogger == nil {
		logger.Initialize()
	}
	err := logger.currentLogger.SendLog(wrapper)
	if err != nil {
		if wslogger, err := logger.currentLogger.(*WebsocketLivelogger); err {
			if err := wslogger.Connect(); err != nil {
				logger.InitializeVssLogger()
				return logger.currentLogger.SendLog(wrapper)
			}
			err := logger.currentLogger.SendLog(wrapper)
			if err != nil {
				logger.InitializeVssLogger()
				return logger.currentLogger.SendLog(wrapper)
			}
			return nil
		}
	}
	return err
}

type BufferedLiveLogger struct {
	LiveLogger
	logchan     chan *TimelineRecordFeedLinesWrapper
	logfinished chan struct{}
}

func (logger *BufferedLiveLogger) sendLogs(logchan chan *TimelineRecordFeedLinesWrapper, logfinished chan struct{}) {
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

func (logger *BufferedLiveLogger) SendLog(wrapper *TimelineRecordFeedLinesWrapper) error {
	if logger.logchan == nil {
		logchan := make(chan *TimelineRecordFeedLinesWrapper, 64)
		logger.logchan = logchan
		logfinished := make(chan struct{})
		logger.logfinished = logfinished
		go logger.sendLogs(logchan, logfinished)
	}
	logger.logchan <- wrapper
	return nil
}

type JobLogger struct {
	JobRequest      *AgentJobRequestMessage
	Connection      *VssConnection
	TimelineRecords *TimelineRecordWrapper
	CurrentRecord   int64
	CurrentLine     int64
	JobBuffer       bytes.Buffer
	CurrentBuffer   bytes.Buffer
	linefeedregex   *regexp.Regexp
	Logger          LiveLogger
	lineBuffer      []byte
}

func (logger *JobLogger) Write(p []byte) (n int, err error) {
	logger.lineBuffer = append(logger.lineBuffer, p...)
	if i := bytes.LastIndexByte(logger.lineBuffer, byte('\n')); i != -1 {
		logger.Log(string(logger.lineBuffer[:i]))
		logger.lineBuffer = logger.lineBuffer[i+1:]
	}
	return len(p), nil
}

func (logger *JobLogger) Current() *TimelineRecord {
	if logger.CurrentRecord < logger.TimelineRecords.Count {
		return logger.TimelineRecords.Value[logger.CurrentRecord]
	}
	return nil
}

func (logger *JobLogger) MoveNext() *TimelineRecord {
	if logger.CurrentBuffer.Len() > 0 {
		if logid, err := logger.Connection.UploadLogFile(logger.JobRequest.Timeline.ID, logger.JobRequest, logger.CurrentBuffer.String()); err == nil {
			logger.Current().Log = &TaskLogReference{ID: logid}
			_ = logger.Update()
		}
	}
	logger.CurrentRecord++
	logger.CurrentLine = 1
	logger.CurrentBuffer.Reset()
	return logger.Current()
}

func (logger *JobLogger) Finish() {
	if logger.JobBuffer.Len() > 0 && len(logger.TimelineRecords.Value) > 0 {
		if logid, err := logger.Connection.UploadLogFile(logger.JobRequest.Timeline.ID, logger.JobRequest, logger.JobBuffer.String()); err == nil {
			logger.TimelineRecords.Value[0].Log = &TaskLogReference{ID: logid}
			_ = logger.Update()
		}
	}
}

func (logger *JobLogger) Update() error {
	return logger.Connection.UpdateTimeLine(logger.JobRequest.Timeline.ID, logger.JobRequest, logger.TimelineRecords)
}

func (logger *JobLogger) Append(record TimelineRecord) *TimelineRecord {
	if l := len(logger.TimelineRecords.Value); l > 0 {
		record.Order = logger.TimelineRecords.Value[l-1].Order + 1
	}
	logger.TimelineRecords.Value = append(logger.TimelineRecords.Value, &record)
	logger.TimelineRecords.Count = int64(len(logger.TimelineRecords.Value))
	return &record
}

func (logger *JobLogger) Insert(record TimelineRecord) *TimelineRecord {
	x := append(make([]*TimelineRecord, 0), logger.TimelineRecords.Value[:logger.CurrentRecord]...)
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
	lines = logger.linefeedregex.ReplaceAllString(strings.TrimSuffix(lines, "\r\n"), "\n")
	_, _ = logger.JobBuffer.WriteString(lines + "\n")
	_, _ = logger.CurrentBuffer.WriteString(lines + "\n")
	cline := logger.CurrentLine
	wrapper := &TimelineRecordFeedLinesWrapper{
		StartLine: &cline,
		Value:     strings.Split(lines, "\n"),
		StepID:    logger.Current().ID,
	}
	wrapper.Count = int64(len(wrapper.Value))
	logger.CurrentLine += wrapper.Count
	timeline := regexp.MustCompile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z ")
	length := len("2021-04-02T15:50:14.6619714Z ")
	for i := 0; i < len(wrapper.Value); i++ {
		if timeline.MatchString(wrapper.Value[i]) {
			wrapper.Value[i] = wrapper.Value[i][length:]
		}
	}
	logger.Logger.SendLog(wrapper)
}
