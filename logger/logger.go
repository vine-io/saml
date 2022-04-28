package logger

import (
	"log"
	"os"
)

// Interface provides the minimal logging interface
type Interface interface {
	// Logf prints to the logger using the format.
	Printf(format string, v ...interface{})
	// Log prints to the logger.
	Print(v ...interface{})
	// Fatal is equivalent to Print() followed by a call to os.Exit(1).
	Fatal(v ...interface{})
	// Fatalf is equivalent to Printf() followed by a call to os.Exit(1).
	Fatalf(format string, v ...interface{})
}

// DefaultLogger logs messages to os.Stdout
var DefaultLogger = log.New(os.Stdout, "", log.LstdFlags)
