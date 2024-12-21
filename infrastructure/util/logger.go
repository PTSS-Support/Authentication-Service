package util

import (
	"context"
	"log/slog"
	"os"
)

type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
	Debug(msg string, args ...any)
	Warn(msg string, args ...any)
	WithContext(ctx context.Context) Logger
}

type logger struct {
	*slog.Logger
	ctx         context.Context
	serviceName string
}

func NewLogger(serviceName string) Logger {
	opts := &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	baseLogger := slog.New(handler)

	// Add service name as a default attribute
	return &logger{
		Logger:      baseLogger.With("service", serviceName),
		serviceName: serviceName,
	}
}

func (l *logger) WithContext(ctx context.Context) Logger {
	return &logger{
		Logger: l.Logger,
		ctx:    ctx,
	}
}

func (l *logger) Info(msg string, args ...any) {
	if l.ctx != nil {
		l.Logger.InfoContext(l.ctx, msg, args...)
		return
	}
	l.Logger.Info(msg, args...)
}

func (l *logger) Error(msg string, args ...any) {
	if l.ctx != nil {
		l.Logger.ErrorContext(l.ctx, msg, args...)
		return
	}
	l.Logger.Error(msg, args...)
}

func (l *logger) Debug(msg string, args ...any) {
	if l.ctx != nil {
		l.Logger.DebugContext(l.ctx, msg, args...)
		return
	}
	l.Logger.Debug(msg, args...)
}

func (l *logger) Warn(msg string, args ...any) {
	if l.ctx != nil {
		l.Logger.WarnContext(l.ctx, msg, args...)
		return
	}
	l.Logger.Warn(msg, args...)
}
