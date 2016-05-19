-----Source Code-----------------------------------------------------------------------
git clone https://github.com/jwyllie83/tcpping

--- Overview ----------------------------------------------------------------

tcpping is a quick utility designed to emulate standard 'ping' in nearly every
meaningful way and only diverge when necessary.  It sends out forged TCP SYN
packets and listens for a SYN/ACK or RST from the server or intermediary.  It
counts and reports on these results using an interface that is nearly identical
to standard UNIX ping.

--- Building ----------------------------------------------------------------

install those libraries with the following:

sudo apt-get install libnet1-dev
sudo apt-get install libpcap-dev

https://dbus.freedesktop.org/releases/dbus/

Or, alternatively, libnet1 is conveniently hosted on GitHub:
http://github.com/sam-github/libnet

While libpcap is hosted at http://www.tcpdump.org/

Build with the following:

make 

if /usr/bin/ld: cannot find -ldbus-1
   install : https://dbus.freedesktop.org/releases/dbus/ ,suggest 1.0.tar.gz

--- Setuid and tcpping ------------------------------------------------------

If you don't want to use root access to use it every time, you can setuid the
program.  Keep in mind that any security vulnerabilities in tcpping could
allow someone to execute arbitrary root-level code, so do this at your own
risk.

sudo chown root:root tcpping
sudo chmod a+s tcpping

----FASTWEB CHANGE LOG----------------------------------------------------

1> add -q, -s , -f , -T option
2> output mdev
3> multiple host 

----Question--------------------------------------------------------------
ifconfig eth0 mtu 1500

---BUG  LOG-------------------------------------------------------------
multiple host ping. case  -s 100
192.168.1.100 --> 192.168.1.101 seq 100:200 length 100
192.168.1.101 --> 192.168.1.100 rst ack 201

192.168.1.100 --> 192.168.1.102 seq 200:300 length 100
192.168.1.102 --> 192.168.1.100 syn/ack ack 201

duplicate ack number
-------------------------------------------------------------------------
