package logger

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logs *zap.Logger

// var sugarLogger *zap.SugaredLogger

func init() {
	var err error

	config := zap.NewProductionConfig()

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.StacktraceKey = zapcore.DPanicLevel.CapitalString()
	encoderConfig.MessageKey = "ACTION"
	config.EncoderConfig = encoderConfig

	dateNow := time.Now()

	//write log
	config.OutputPaths = []string{
		fmt.Sprintf("log/data/logger-%s.log", dateNow.Format("2006-01-02")),
	}

	logs, err = config.Build(zap.AddCallerSkip(1))

	if err != nil {
		panic(err)
	}

}

func Info(message string, fields ...zap.Field) {
	logs.Info(message, fields...)

}

func Debug(message string, fields ...zap.Field) {
	logs.Debug(message, fields...)
}

func Error(message string, fields ...zap.Field) {
	logs.Error(message, fields...)

}
