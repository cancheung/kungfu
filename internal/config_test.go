package internal

import (
	"fmt"
	"testing"
)

func TestParseConfig(t *testing.T) {
	config, err := ParseConfig("../dns/server/config.yml")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("config: %v\n", config)
}
