package internal

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"os"
)

const (
	// NAMESPACE is for redis preifx(namespace)
	NAMESPACE = "kungfu"
)

// Redis is config.yml redis struct
type Redis struct {
	Addr     string
	Password string
}

func (r *Redis) String() string {
	return fmt.Sprintln("addr:", r.Addr, "Password:", r.Password)
}

// Config is struct commom config.yml
type Config struct {
	Redis Redis
}

func (config *Config) String() string {
	return fmt.Sprintln(
		"redis:", config.Redis)
}

// ParseConfig parse the config file
func ParseConfig(file string) *Config {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		log.Error("%v", err)
		os.Exit(1)
	}

	config := new(Config)

	err = yaml.Unmarshal(data, config)

	if err != nil {
		log.Error("get config error, %v", err)
		os.Exit(1)
	}

	return config
}

// ParseNetwork parse the network get minip maxip
func ParseNetwork(network string) (minIp uint32, maxIp uint32, err error) {
	ip, subnet, err := net.ParseCIDR(network)
	if err != nil {
		return
	}

	if ip = ip.To4(); ip == nil || ip[3] == 0 {
		err = errors.New(fmt.Sprintf("invalid network %s", network))
		return
	}

	minIp = Ipv4ToInt(subnet.IP) + 1
	maxIp = minIp + ^Ipv4ToInt(net.IP(subnet.Mask)) - 1

	return
}

// GetRedisKey get the commom redis key, with namespace
func GetRedisKey(k string) string {
	return fmt.Sprintf("%s:%s", NAMESPACE, k)
}

// GetRedisNetworkKey get network config key
func GetRedisNetworkKey() string {
	return GetRedisKey("network")
}

// GetRedisUpstreamNameserverKey get upstream nameserver config key
func GetRedisUpstreamNameserverKey() string {
	return GetRedisKey("upstream-nameserver")
}

// GetRedisDomainKey get domain config key
func GetRedisDomainKey(domain string) string {
	return GetRedisKey(fmt.Sprintf("cache:domain-%s", domain))
}

// GetRedisIpKey get redis ip cache config
func GetRedisIpKey(ip string) string {
	return GetRedisKey(fmt.Sprintf("cache:ip-%s", ip))
}

// GetRedisRealIpKey get redis real ip cache key
func GetRedisRealIpKey(ip string) string {
	return GetRedisKey(fmt.Sprintf("cache:ip-real-%s", ip))
}

// GetRedisProxyKey get redis proxy config key
func GetRedisProxyKey() string {
	return GetRedisKey("proxy")
}

// GetRedisRelayPortKey get redis relay-port config key
func GetRedisRelayPortKey() string {
	return GetRedisKey("relay-port")
}

// GetRedisProxyDomainSetKey get redis proxy domain set key
func GetRedisProxyDomainSetKey() string {
	return GetRedisKey("gfwlist")
}

// GetRedisNetworkChannelKey get redis network channel key
func GetRedisNetworkChannelKey() string {
	return GetRedisKey("network-channel")
}

// GetRedisProxyChannelKey get redis proxy channel key
func GetRedisProxyChannelKey() string {
	return GetRedisKey("proxy-channel")
}
