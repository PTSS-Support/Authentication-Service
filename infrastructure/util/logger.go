package util

import (
	"context"
	"github.com/rs/zerolog"
	"os"
	"regexp"
	"strings"
)

var sensitiveFields = map[string]bool{
	"password":    true,
	"pin":         true,
	"oldPassword": true,
	"newPassword": true,
	"oldPin":      true,
	"newPin":      true,
	"token":       true,
	"secret":      true,
}

// patterns for sanitization
var (
	emailPattern = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	uuidPattern  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func sanitizeString(s string) string {
	// Remove control characters, newlines, and carriage returns
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1 // Drop the character
		}
		return r
	}, s)

	s = strings.ReplaceAll(s, "\u0000", "") // Null byte
	s = strings.ReplaceAll(s, "\u2028", "") // Line separator
	s = strings.ReplaceAll(s, "\u2029", "") // Paragraph separator

	return s
}

func sanitizeValue(key string, value interface{}) interface{} {
	if value == nil {
		return nil
	}

	strValue, ok := value.(string)
	if ok {
		strValue = sanitizeString(strValue)
	}

	if sensitiveFields[strings.ToLower(key)] {
		return "[REDACTED]"
	}

	switch {
	case key == "email" || strings.Contains(strings.ToLower(key), "email"):
		if emailPattern.MatchString(strValue) {
			parts := strings.Split(strValue, "@")
			username := parts[0]
			if len(username) > 3 {
				return username[:3] + "***@" + parts[1]
			}
		}
	case strings.Contains(strings.ToLower(key), "id"):
		if uuidPattern.MatchString(strValue) {
			return strValue[:8] + "..." + strValue[len(strValue)-4:]
		}
	}

	return value
}

type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
	Debug(msg string, args ...any)
	Warn(msg string, args ...any)
	WithContext(ctx context.Context) Logger
}

type logger struct {
	log         zerolog.Logger
	ctx         context.Context
	serviceName string
}

func NewLogger(serviceName string) Logger {
	// Configure console writer with colors
	output := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "2006-01-02T15:04:05.000Z07:00",
		NoColor:    false,
	}

	// Create logger
	log := zerolog.New(output).
		Level(zerolog.DebugLevel).
		With().
		Timestamp().
		Str("service", serviceName).
		Caller().
		Logger()

	return &logger{
		log:         log,
		serviceName: serviceName,
	}
}

func (l *logger) WithContext(ctx context.Context) Logger {
	return &logger{
		log:         l.log,
		ctx:         ctx,
		serviceName: l.serviceName,
	}
}

func (l *logger) Info(msg string, args ...any) {
	logEvent := l.log.Info()
	addFields(logEvent, args...)
	logEvent.Msg(msg)
}

func (l *logger) Error(msg string, args ...any) {
	logEvent := l.log.Error()
	addFields(logEvent, args...)
	logEvent.Msg(msg)
}

func (l *logger) Debug(msg string, args ...any) {
	logEvent := l.log.Debug()
	addFields(logEvent, args...)
	logEvent.Msg(msg)
}

func (l *logger) Warn(msg string, args ...any) {
	logEvent := l.log.Warn()
	addFields(logEvent, args...)
	logEvent.Msg(msg)
}

func addFields(event *zerolog.Event, args ...any) {
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			key, ok := args[i].(string)
			if ok {
				// Sanitize the value before adding to log
				sanitizedValue := sanitizeValue(key, args[i+1])
				event.Interface(key, sanitizedValue)
			}
		}
	}
}
