package logging

import (
	"log"
	"os"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"
)

func getLogFilePath() string {
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Can not detect the executable path: %v", err)
	}

	// get name from path
	execFilename := filepath.Base(execPath)

	// get home path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Can not get the home path: %v", err)
	}

	// log file path
	logFilePath := filepath.Join(homeDir, execFilename+".log")
	return logFilePath
}

// Function to set up logging to a file
func SetupLogging(logFilePath string) *lumberjack.Logger {
	if logFilePath == "" {
		logFilePath = getLogFilePath()
	}

	logger := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    5, // MB
		MaxBackups: 1,
		MaxAge:     1, // days
		LocalTime:  true,
		Compress:   false,
	}

	log.SetOutput(logger)
	// log.SetFlags(log.Lshortfile | log.LstdFlags)
	log.SetFlags(log.LstdFlags)
	return logger
}
