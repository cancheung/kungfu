package main

import (
	"flag"
	"fmt"
	"github.com/yinheli/kungfu"
	"github.com/yinheli/kungfu/dns"
	"github.com/yinheli/kungfu/internal"
	"os"
)

var (
	log   = kungfu.GetLog()
	build string

	c       = flag.String("c", "config.yml", "config file")
	d       = flag.Bool("d", false, "debug log level")
	version = flag.Bool("version", false, "show server version")
)

func main() {
	ver := getVersion()

	u := flag.Usage
	flag.Usage = func() {
		fmt.Printf("\n%s dns %v\n", kungfu.Name, ver)
		fmt.Println("  maintained by yinheli<hi@yinheli.com>\n")
		u()
	}

	flag.Parse()

	if !flag.Parsed() {
		flag.Usage()
		os.Exit(1)
	}

	if *version {
		fmt.Printf("version: %s\n", ver)
		os.Exit(0)
	}

	if *d {
		kungfu.SetLogLevelDebug()
	}

	log.Info("kungfu dns server version: %s", ver)
	log.Info(kungfu.DECLARATION)

	config := internal.ParseConfig(*c)
	client := internal.NewRedisClient(&config.Redis)

	server := &dns.Server{
		RedisClient: client,
	}

	server.Start()
}

func getVersion() string {
	if build == "" {
		return fmt.Sprintf("%s", kungfu.Version)
	}
	return fmt.Sprintf("%s build: %s", kungfu.Version, build)
}
