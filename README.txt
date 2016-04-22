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

Or, alternatively, libnet1 is conveniently hosted on GitHub:
http://github.com/sam-github/libnet

While libpcap is hosted at http://www.tcpdump.org/

Build with the following:

make

--- Setuid and tcpping ------------------------------------------------------

If you don't want to use root access to use it every time, you can setuid the
program.  Keep in mind that any security vulnerabilities in tcpping could
allow someone to execute arbitrary root-level code, so do this at your own
risk.

sudo chown root:root tcpping
sudo chmod a+s tcpping

----FASTWEB CHANGE LOG----------------------------------------------------

1> add -q, -s option
2> output mdev

----Question--------------------------------------------------------------
ifconfig eth0 mtu 1500
