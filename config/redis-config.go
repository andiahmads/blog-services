package config

import (
	"fmt"
	"os"

	"github.com/go-redis/redis/v7"
)

func SetupRedisConnection() *redis.Client {

	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client := redis.NewClient(&redis.Options{
		Addr:     dsn, //redis port
		Password: "",
		DB:       0,
	})
	pong, err := client.Ping().Result()
	fmt.Println(pong, err)
	if err != nil {
		panic(err)
	}

	return client

}
