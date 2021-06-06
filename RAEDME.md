# Packet sniffer

Simple packet sniffer with backups to S3.

To configure:

Add a `.env` file and add env vars for your aws access key, secret key and s3 bucket name.

Compile normally using cargo.

To see list of available devices use

```shell
./sniffer --p
```

To start sniffing on a device use:

```shell
./sniffer --d [device name]
```
