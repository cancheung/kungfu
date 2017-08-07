package internal

import (
	"os"

	"github.com/go-redis/redis"
	"github.com/yinheli/kungfu"
)

var (
	log = kungfu.GetLog()
)

// NewRedisClient is for create new redis client via config
func NewRedisClient(config *Redis) (client *redis.Client) {
	client = redis.NewClient(&redis.Options{
		Addr:     config.Addr,
		Password: config.Password,
	})

	if err := client.Ping().Err(); err != nil {
		log.Error("test redis fail %v", err)
		os.Exit(1)
	}

	return
}
