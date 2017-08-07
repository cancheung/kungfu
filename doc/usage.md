# 安装和使用

kungfu 使用 go 语言开发，只做了 linux 的兼容。

## 工作原理

1. 内置 DNS 服务，针对白名单域名返回特定的内网 IP
2. 内网配置静态路由规则，网关劫持流量，做 `fq` 处理

优点：

内网可实现无感知全自动 `fq`。
DSN server, gateway server, socks5 server 都能做水平扩容，理论上可以支持很大的网络。比较适合有需要的企业内部使用。

缺点：

不支持直接 IP fq，比如 `172.217.25.14` 这个 IP 已挂，直接访问这个 IP 流量不经过特定的网关，无法处理。

## 环境准备

1. 安装提供 `socks5` 的代理软件，这里推荐 `shadowsocks`, 或者其他衍生版本，请按照自己的喜好选择即可。
2. 安装 `redis`，用于配置存储和 DNS 查询记录缓存


## 编译安装

> 也可以跳过这一步，直接使用预编译的二进制版本。

```
git clone git@github.com:yinheli/kungfu.git
./release.sh
```

编译后生成的可执行文件在 `release` 文件夹中。

## 初始化配置

除 `config.yml` 中的配置外，其他配置均存储在 `redis` 中。

> 计划通过 web ui 完成，但目前 web ui 尚未完成，暂时先通过手工初始化配置数据。

```
# 配置网络，注意不和内网环境冲突即可
redis-cli set kungfu:network 10.85.0.1/16

# 配置上游 DNS 服务，多个服务用逗号分割，一般配置 2 个足以
# 这里配置的是 DNSpod 和 阿里 的公共 DNS
redis-cli set kungfu:upstream-nameserver 119.29.29.29,223.5.5.5

# 配置 socks5 地址
redis-cli set kungfu:proxy socks5://127.0.0.1:1988

# 配置 relay 端口，仅程序内部使用，确保这个端口服务器未被占用即可
redis-cli set kungfu:relay-port 1985

# 增加需要处理的域名
# 建议把整个 gfwlist 都添加进去，
# 请参考： https://gist.github.com/yinheli/39e6eb5a6e9ba0b29e056ca476539b2a
# 注意，子域名是自动包含的。
redis-cli sadd kungfu:gfwlist google.com
redis-cli sadd kungfu:gfwlist google.com.hk
```

修改 `config.yml` 中的 `redis` 的配置

## 启动服务

> 首次使用，建议添加 `-d` 参数，开启 debug 模式，打印更多的日志，遇到问题时方便排查

```
# 启动 DNS 服务
./kungfu-dns-server

# 启动 网关 服务
./kungfu-gateway-server
```

## 配置路由

### 配置静态路由

在路由器上配置一条静态路由，配置信息如下（请和上面配置的网络一致）

目的IP地址 | 子网掩码    | 网关
---------- | ----------- | --------------
10.85.0.0 | 255.255.0.0 | 192.168.9.88（kungfu-gateway-server 程序所在的服务器 IP）

### 修改 DHCP 配置

> 注意，在未完成测试前，建议先不改，以免服务故障，导致内网其他人可能无法上网（解析 DNS）。

将 DHCP 配置中的网关改为 kungfu-dns-server 所在服务器的 IP（192.168.9.88）

## 测试

```
ping google.com
```

如果服务器返回 10.85.x.x 这样的 ip，则表示工作正常，kungfu-dns-server, kungfu-gateway-server 也会输出相关日志。
