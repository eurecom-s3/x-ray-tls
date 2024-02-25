# Linux traffic control



sudo tc qdisc add dev enx98e743da6832 clsact handle 10: netem delay 3000ms


sudo tc class add dev enx98e743da6832 parent 1:1 classid :1 htb rate 100Mbps

sudo tc qdisc add dev enx98e743da6832 parent 1:1 handle 10: netem delay 3000ms










## Steps

- Replace default qdisc with a classful qdisc
default 10 = default class is class 10
`sudo tc qdisc add dev enx98e743da6832 handle 1: root htb default 10`

-  Add class for normal traffic
`sudo tc class add dev enx98e743da6832 parent 1: classid 10 htb rate 100Mbps`
TODO: is `rate 100Mbps` limiting bandwidth?

- Add class for ServerHello traffic
`sudo tc class add dev enx98e743da6832 parent 1: classid 20 htb rate 1Mbps`

- Delay ServerHello traffic class
`sudo tc qdisc add dev enx98e743da6832 parent 1:20 handle 10 netem delay 10000ms`


Delay all
sudo tc filter add dev enx98e743da6832 protocol ip parent 1: prio 1 u32 match ip dport 443 0xffff flowid 1:20

## Remove

`sudo tc qdisc del dev enx98e743da6832 root`


## Q/A
alias tc_state="sudo tc qdisc show dev enx98e743da6832; sudo tc class show dev enx98e743da6832; sudo tc filter show dev enx98e743da6832"
Note: device must be specified

Q: Why replacing default qdisc?
A: By default, interface uses qdisc fq_codel.
However, fq_codel is classless.


# Notes
- with HTB, you should attach all filters to the root!

- Delay all traffic to port 443
`sudo tc filter add dev enx98e743da6832 protocol ip parent 1: prio 1 u32 match ip dport 443 0xffff classid 1:20`

- HTB by default attaches `pfifo` as leaf qdisc


# Web resources
- <https://man7.org/linux/man-pages/man8/tc-bpf.8.html>
- <https://github.com/iovisor/bcc/blob/master/examples/networking/tc_perf_event.py>
- <https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/>
- <https://legacy.netdevconf.info/0x14/pub/slides/55/slides.pdf>
