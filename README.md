# ssh-secure
listen /var/log/secure, add any invalid ip address to /etc/hosts.deny, use inotify, not busy loop.

# build

```bash
export GO111MODULE=on
go mod init secure
go build
./secure
```
