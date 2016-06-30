# twemproxy (nutcracker) [![Build Status](https://secure.travis-ci.org/twitter/twemproxy.png)](http://travis-ci.org/twitter/twemproxy)

**twemproxy** (pronounced "two-em-proxy"), aka **nutcracker** is a fast and lightweight proxy for [memcached](http://www.memcached.org/) and [redis](http://redis.io/) protocol. It was built primarily to reduce the number of connections to the caching servers on the backend. This, together with protocol pipelining and sharding enables you to horizontally scale your distributed caching architecture.


## NEW FEATURE

    We modified the twemproxy to supports redis-server failover by communicating with redis-sentinel^_^
![image](http://nos.netease.com/knowledge/9e4c3186-3994-41e8-bf9e-924ff56d4ac9)
## Build

To build twemproxy from source with _debug logs enabled_ and _assertions enabled_:

    $ git clone git@github.com:twitter/twemproxy.git
    $ cd twemproxy
    $ autoreconf -fvi
    $ ./configure --enable-debug=full
    $ make
    $ src/nutcracker -h

## Help

    Usage: nutcracker [-?hVdDt] [-v verbosity level] [-o output file]
                      [-c conf file] [-s stats port] [-a stats addr]
                      [-i stats interval] [-p pid file] [-m mbuf size]

    Options:
      -h, --help             : this help
      -V, --version          : show version and exit
      -t, --test-conf        : test configuration for syntax errors and exit
      -d, --daemonize        : run as a daemon
      -D, --describe-stats   : print stats description and exit
      -v, --verbose=N        : set logging level (default: 5, min: 0, max: 11)
      -o, --output=S         : set logging file (default: stderr)
      -c, --conf-file=S      : set configuration file (default: conf/nutcracker.yml)
      -s, --stats-port=N     : set stats monitoring port (default: 22222)
      -a, --stats-addr=S     : set stats monitoring ip (default: 0.0.0.0)
      -i, --stats-interval=N : set stats aggregation interval in msec (default: 30000 msec)
      -p, --pid-file=S       : set pid file (default: off)
      -m, --mbuf-size=N      : set size of mbuf chunk in bytes (default: 16384 bytes)

    For example:
      nutcracker -d -v 5 -o nutcracker.log -c nutcracker.yml -i 10000 -p nutcracker.pid

## Configuration

Twemproxy can be configured through a YAML file specified by the -c or --conf-file command-line argument on process start. The configuration file is used to specify the server pools and the servers within each pool that twemproxy manages. The configuration files parses and understands the following keys:

+ **listen**: The listening address and port (name:port or ip:port) or an absolute path to sock file (e.g. /var/run/nutcracker.sock) for this server pool.
+ **client_connections**: The maximum number of connections allowed from redis clients. Unlimited by default, though OS-imposed limitations will still apply.
+ **hash**: The name of the hash function. Possible values are:
 + one_at_a_time
 + md5
 + crc16
 + crc32 (crc32 implementation compatible with [libmemcached](http://libmemcached.org/))
 + crc32a (correct crc32 implementation as per the spec)
 + fnv1_64
 + fnv1a_64
 + fnv1_32
 + fnv1a_32
 + hsieh
 + murmur
 + jenkins
+ **hash_tag**: A two character string that specifies the part of the key used for hashing. Eg "{}" or "$$". [Hash tag](notes/recommendation.md#hash-tags) enable mapping different keys to the same server as long as the part of the key within the tag is the same.
+ **distribution**: The key distribution mode. Possible values are:
 + ketama
 + modula
 + random
+ **timeout**: The timeout value in msec that we wait for to establish a connection to the server or receive a response from a server. By default, we wait indefinitely.
+ **backlog**: The TCP backlog argument. Defaults to 512.
+ **tcpkeepalive**: A boolean value that controls if a server pool set keepalive on every connection. Defaults to false.
+ **redis_auth**: Authenticate to the Redis server on connect.
+ **redis_db**: The DB number to use on the pool servers. Defaults to 0. Note: Twemproxy will always present itself to clients as DB 0.
+ **server_connections**: The maximum number of connections that can be opened to each server. By default, we open at most 1 server connection.
+ **groups**: A list of server groups, that are used for partition. At the same time, they are monitored in redis-sentinels.
+ **sentinel_heartbeat**: The number of consecutive failures on a server that would lead to it being temporarily ejected when auto_eject_host is set to true. Defaults to 2.
+ **sentinels**: A list of redis-sentinel address, port and name (ip:port or ip:port name) for this server pool.

For example
        alpha:
          listen: 0.0.0.0:6379
          hash: murmur
          hash_tag: "{}"
          distribution: ketama
          timeout: 400
          redis_auth: 123456
          groups:
           - groups_helf_0
           - groups_helf_1
           - groups_helf_2
           - groups_helf_3
          sentinel_heartbeat: 2000
          sentinels:
           - 10.164.97.188:26379 sentinel0
           - 10.164.97.189:26379 sentinel1
           - 10.164.97.190:26379 sentinel2
