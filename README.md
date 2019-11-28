# nisl_360_dns
dns_data_processing

## How to build

### Dependency

My programs depends on these libraries:

- jsoncpp
- libpcap
- pcapplusplus
- openssl

On Macos:

```bash
brew install jsoncpp libpcap pcapplusplus openssl
ln -s /usr/local/opt/openssl/lib/libcrypto.1.0.0.dylib /usr/local/lib/
ln -s /usr/local/opt/openssl/lib/libcrypto.a /usr/local/lib/
ln -s /usr/local/opt/openssl/lib/libssl.a /usr/local/lib/
ln -s /usr/local/opt/openssl/lib/libssl.1.0.0.dylib /usr/local/lib/
ln -s /usr/local/opt/openssl/include/openssl /usr/local/include
```

On Linux:

```bash
sudo apt install libpcap-dev libjsoncpp-dev openssl
```

and then install `pcapplusplus` through its [doc](http://seladb.github.io/PcapPlusPlus-Doc/download.html#linux) and [release page](https://github.com/seladb/PcapPlusPlus/releases).

### Build

```bash
mkdir Release
cd Release
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```
Caplen ：调整不同pcap文件参数保证后续处理一致性
Mac:调整pcap文件mac地址，目前是统一替换，可使用配置文件进行修改
IP：IP地址随机映射，包含网络层源和目的IP地址，以及应用层中DNS协议包含的IP应答信息
Domain：域名哈希替换。后缀替换与子域名哈希截断替换
Checksum:校验和重算
