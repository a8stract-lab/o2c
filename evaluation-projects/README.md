# evaluation


## ipv6

```
python -m http.server --bind ::1  8000

ab -n 100 -c 10 http://[::1]:8000/

curl -6 http://[::1]:8000/


# create test files 100kb 1mb 10mb
dd if=/dev/zero of=100kb.test bs=100KB count=1
dd if=/dev/zero of=1mb.test bs=1MB count=1
dd if=/dev/zero of=10mb.test bs=10MB count=1


ab -n 100 -c 10 http://[::1]:8000/100kb.test
ab -n 100 -c 10 http://[::1]:8000/1mb.test
ab -n 100 -c 10 http://[::1]:8000/10mb.test

```