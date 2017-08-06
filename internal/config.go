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
	NAMESPACE = "kungfu"
)

type Redis struct {
	Addr     string
	Password string
}

func (r *Redis) String() string {
	return fmt.Sprintln("addr:", r.Addr, "Password:", r.Password)
}

type Config struct {
	Redis Redis
}

func (config *Config) String() string {
	return fmt.Sprintln(
		"redis:", config.Redis)
}

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

func GetRedisKey(k string) string {
	return fmt.Sprintf("%s:%s", NAMESPACE, k)
}

func GetRedisNetworkKey() string {
	return GetRedisKey("network")
}

func GetRedisUpstreamNameserverKey() string {
	return GetRedisKey("upstream-nameserver")
}

func GetRedisDomainKey(domain string) string {
	return GetRedisKey(fmt.Sprintf("cache:domain-%s", domain))
}

func GetRedisIpKey(ip string) string {
	return GetRedisKey(fmt.Sprintf("cache:ip-%s", ip))
}

func GetRedisRealIpKey(ip string) string {
	return GetRedisKey(fmt.Sprintf("cache:ip-real-%s", ip))
}

func GetRedisProxyKey() string {
	return GetRedisKey("proxy")
}

func GetRedisRelayPortKey() string {
	return GetRedisKey("relay-port")
}

func GetRedisProxyDomainSetKey() string {
	return GetRedisKey("gfwlist")
}

func GetRedisNetworkChannelKey() string {
	return GetRedisKey("network-channel")
}

func GetRedisProxyChannelKey() string {
	return GetRedisKey("proxy-channel")
}
