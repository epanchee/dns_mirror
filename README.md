# DNS traffic mirroring tool (**dns-mirror**)

### Description

Userspace libpcap-based tool. **dns-mirror** sniffs dns packets on the given interface and proxies it to the given address on port 53.

### Why?

It can be useful for monitoring purposes in your private network. The advantage of this tool is that you do not need to
inject it in the middle of your network and cause probable fault. It works from the side just as a mirror.

### How to run

You need superuser rights to run **dns-mirror**.
```bash
sudo dns-mirror -d br0 -i 10.30.1.100
```

### Example
```bash
dns-mirror --help
DNS traffic mirroring daemon 0.1.0

USAGE:
    dns-mirror [FLAGS] [OPTIONS] --dev <dev> --ip <ip>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
        --verbose    Show debug messages

OPTIONS:
    -d, --dev <dev>      Device to sniff
    -i, --ip <ip>        DNS server IP
    -p, --port <port>    DNS server port. Default: 53
```

```bash
~ # dns-mirror -d br0 -i 10.30.1.100  --verbose
 2021-12-05T14:02:28.440Z DEBUG dns_mirror > Dns from 10.30.1.43 mirrored to 10.30.1.100:53
 2021-12-05T14:02:28.833Z DEBUG dns_mirror > Dns from 10.30.1.38 mirrored to 10.30.1.100:53
 2021-12-05T14:02:49.191Z DEBUG dns_mirror > Dns from 10.30.1.87 mirrored to 10.30.1.100:53
 2021-12-05T14:03:26.595Z DEBUG dns_mirror > Dns from 10.30.1.98 mirrored to 10.30.1.100:53
 ...
 ```

### Limitations

- If you want to monitor all users then you have to connect all interfaces to the bridge and sniff on it (on most
  routers it is default).
- At the moment dns sniffs only udp packets sent to dst port 53. Thus, it does not monitor tricky users who use
  customized dns requests.
- As well as it can not sniff DoH/DoT requests.
- TCP DNS requests are not covered yet
- It does not check that the received packet is actually DNS-packet.

### Build

The project was successfully built and launched on **MediaTek MT7621 SoC (MIPS 1004Kc V2.15)**  
Repository is supplied with custom Docker image and Cross.toml to build libpcap for mipsel-unknown-linux-gnu arch.
Use powerful [cross](https://github.com/rust-embedded/cross) to build it.

#### How to build

```bash
( cd build; docker build -t crossbuild_mipsel:local . )

cat >> cat ~/.cargo/config
[target.mipsel-unknown-linux-gnu]
rustflags = ["-C", "target-feature=+crt-static", "-lpcap"]

cross build --target mipsel-unknown-linux-gnu --release
```