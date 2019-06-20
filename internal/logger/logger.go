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

type BufferedFormatter struct {
	q []*logrus.Entry
}

func (b *BufferedFormatter) Format(e *logrus.Entry) ([]byte, error) {
	if b.q == nil {
		b.q = make([]*logrus.Entry, 0, 30)
	}
	b.q = append(b.q, e)
	return nil, nil
}

func SetFormat(log *logrus.Logger, useJSON bool) {
	var q []*logrus.Entry
	if f, ok := log.Formatter.(*BufferedFormatter); ok {
		q = f.q
	}
	if useJSON {
		log.Formatter = UTCFormatter{&logrus.JSONFormatter{
			TimestampFormat: time.RFC1123,
		}}
	} else {
		log.Formatter = UTCFormatter{&logrus.TextFormatter{
			TimestampFormat:  time.RFC1123,
			QuoteEmptyFields: true,
		}}
	}
	for _, e := range q {
		// process the entry
		ftd, err := log.Formatter.Format(e)
		if err != nil {
			continue // do we really want to log.. an error logging?
		}
		fmt.Fprint(log.Out, string(ftd))
	}
}

func NewBuffered() *logrus.Logger {
	log := logrus.New()
	log.Formatter = &BufferedFormatter{}
	return log
}

func New(json bool) *logrus.Logger {
	log := logrus.New()
	SetFormat(log, json)
	return log
}

type ChiLogger struct{ l *logrus.Logger }

func NewChi(log *logrus.Logger) *ChiLogger {
	return &ChiLogger{log}
}

func (cl *ChiLogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	scheme := "http"
	if r.TLS != nil {
		scheme += "s"
	}

	entry := &ChiLogEntry{logrus.NewEntry(cl.l)}
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

func (cl *ChiLogger) L() *logrus.Logger { return cl.l }

type ChiLogEntry struct {
	l logrus.FieldLogger
}

func (cle *ChiLogEntry) Write(status int, bytes int, elapsed time.Duration) {
	cle.l = cle.l.WithFields(logrus.Fields{
		"resp_status":     status,
		"resp_bytes_len":  bytes,
		"resp_elapsed_ms": float64(elapsed.Nanoseconds()) / 1000000.0,
	})
	cle.l.Infoln("request complete")
}

func (cle *ChiLogEntry) Panic(v interface{}, stack []byte) {
	cle.l = cle.l.WithFields(logrus.Fields{
		"stack": string(stack),
		"panic": fmt.Sprintf("%+v", v),
	})
}

/* --- handler log -setter helper -----*/

func GetLog(r *http.Request) logrus.FieldLogger {
	entry := middleware.GetLogEntry(r).(*ChiLogEntry)
	return entry.l
}

func Log(r *http.Request, key string, value interface{}) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*ChiLogEntry); ok {
		entry.l = entry.l.WithField(key, value)
	}
}
