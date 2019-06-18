package logger

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"

	"github.com/sirupsen/logrus"
)

type UTCFormatter struct{ logrus.Formatter }

func (u UTCFormatter) Format(e *logrus.Entry) ([]byte, error) {
	e.Time = e.Time.UTC()
	return u.Formatter.Format(e)
}

type Logger struct{ l *logrus.Logger }

func New(json bool) *Logger {
	log := logrus.New()
	if json {
		log.Formatter = UTCFormatter{&logrus.JSONFormatter{
			TimestampFormat: time.RFC1123,
		}}
	}
	return &Logger{log}
}

func (sl *Logger) NewLogEntry(r *http.Request) middleware.LogEntry {
	scheme := "http"
	if r.TLS != nil {
		scheme += "s"
	}

	entry := &LogEntry{logrus.NewEntry(sl.l)}
	pf := logrus.Fields{
		"remote_addr": r.RemoteAddr,
		"user_agent":  r.UserAgent(),
		"uri":         fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI),
	}
	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		pf["reqID"] = reqID
	}

	entry.l = entry.l.WithFields(pf)
	entry.l.WithFields(logrus.Fields{
		"http_scheme": scheme,
		"http_proto":  r.Proto,
		"http_method": r.Method,
		"headers":     r.Header,
	}).Infoln("request started")

	return entry
}

func (sl *Logger) L() *logrus.Logger { return sl.l }

type LogEntry struct {
	l logrus.FieldLogger
}

func (le *LogEntry) Write(status int, bytes int, elapsed time.Duration) {
	le.l = le.l.WithFields(logrus.Fields{
		"resp_status":     status,
		"resp_bytes_len":  bytes,
		"resp_elapsed_ms": float64(elapsed.Nanoseconds()) / 1000000.0,
	})
	le.l.Infoln("request complete")
}

func (le *LogEntry) Panic(v interface{}, stack []byte) {
	le.l = le.l.WithFields(logrus.Fields{
		"stack": string(stack),
		"panic": fmt.Sprintf("%+v", v),
	})
}

/* --- handler log -setter helper -----*/

func GetLog(r *http.Request) logrus.FieldLogger {
	entry := middleware.GetLogEntry(r).(*LogEntry)
	return entry.l
}

func Log(r *http.Request, key string, value interface{}) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*LogEntry); ok {
		entry.l = entry.l.WithField(key, value)
	}
}
