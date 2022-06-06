# Performance 

## Version v0.2.0

### Version

```bash
git clone https://github.com/nginx/nginx -b release-1.17.8
git clone https://github.com/openssl/openssl -b OpenSSL_1_1_1g
git clone https://github.com/phuslu/nginx-ssl-fingerprint -b v0.1.0
```

### Server

| Type   | Service             | Cores | Memeory(G) |
| ------ | ------------------- | ----- | ---------- |
| Server | nginx with 5 worker | 8     | 8          |
| Client | wrk                 | 8     | 8          |

### Performance Results

```bash
for i in $(seq 1 10); do
    wrk https://localhost/  --latency -t48 -d15 -c2000  >/tmp/wrk.log.$i
done
```

- QPS: Average Req/Second in 10 times
- Latency: Average 50% latency (ms) in 10 times

| WRK Connection | QPS Cost | Origin Req/Sec | Origin Latency | Req/Sec with fingerprint | Latency with fingerprint |
| -------------- | -------- | -------------- | -------------- | ------------------------ | ------------------------ |
| 50             | 4.3%     | 75896.9        | 571.4us        | 72599.5                  | 597.9us                  |
| 100            | 3.2%     | 80044.3        | 1.105          | 77492.3                  | 1.125                    |
| 200            | 5.2%     | 87101.5        | 2.063          | 82601.1                  | 2.144                    |
| 500            | 4.6%     | 93582.7        | 5.048          | 89311.6                  | 5.282                    |
| 1000           | 6.6%     | 96417.9        | 9.802          | 90020.6                  | 10.519                   |
| 1500           | 6.8%     | 95786.3        | 12.688         | 89246                    | 13.868                   |
| 2000           | 5.1%     | 94399.1        | 14.38          | 89553.4                  | 91030.35                 |
