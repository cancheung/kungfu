package kungfu

import (
	"github.com/op/go-logging"
	"os"
)

const module = "kungfu"

var (
	log          = logging.MustGetLogger(module)
	levelBackend logging.LeveledBackend
)

func init() {
	format := logging.MustStringFormatter(
		"%{time:2006-01-02 15:04:05.000} [%{level:.4s}] - %{message}",
	)

	backend := logging.NewLogBackend(os.Stdout, "", 0)
	levelBackend = logging.AddModuleLevel(logging.NewBackendFormatter(backend, format))
	levelBackend.SetLevel(logging.INFO, module)
	log.SetBackend(levelBackend)
}

func GetLog() *logging.Logger {
	return log
}

func SetLogLevelDebug() {
	levelBackend.SetLevel(logging.DEBUG, module)
}
