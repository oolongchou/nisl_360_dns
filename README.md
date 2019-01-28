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
brew insall jsoncpp libpcap pcapplusplus openssl
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
