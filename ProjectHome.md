**NOTE: On aug.28, 2014 there will be a netmap tutorial at Hot Interconnects, Mountain View. See  http://www.hoti.org/hoti22/tutorials/#tut4 for more information.**


---


This project adds netmap support to the bhyve hypervisor. Together with the
netmap and virtio code committed in FreeBSD-HEAD [r270063](https://code.google.com/p/netmap-bhyve/source/detail?r=270063) (and soon to be
merged in FreeBSD 10) guest VMs reach over 1Mpps with standard APIs
(e.g. libpcap), and 5-8 Mpps in netmap mode.


See http://info.iet.unipi.it/~luigi/netmap for more details on netmap.

Other related repositories of interest (in all cases we track the original repositories and will try to upstream our changes):
  * https://code.google.com/p/netmap/ the most recent netmap source code
  * https://code.google.com/p/netmap-libpcap  a netmap-enabled version of libpcap from https://github.com/the-tcpdump-group/libpcap.git . With this, basically any pcap client can read/write traffic at 10+ Mpps, with zerocopy reads and (soon) support for  zerocopy writes
  * https://code.google.com/p/netmap-click a netmap-enabled version of the Click Modular Router from git://github.com/kohler/click.git . This version matches the current version of netmap, supporting all features (including netmap pipes)
  * https://code.google.com/p/netmap-ipfw a netmap-enabled, userspace version of the ipfw firewall and  [dummynet](http://info.iet.unipi.it/~luigi/dummynet/) network emulator. This version reaches 7-10 Mpps for filtering and over 2.5 Mpps for emulation.


[Related publications](http://info.iet.unipi.it/~luigi/research.html)

  * Luigi Rizzo, Giuseppe Lettieri, Vincenzo Maffione, **Speeding up packet I/O in virtual machines,** IEEE/ACM ANCS 2013, San Jose, Oct 2013
  * Luigi Rizzo, Giuseppe Lettieri, **VALE: a switched ethernet for virtual machines,** ACM CoNEXT'2012, Nice, France
  * Luigi Rizzo, **netmap: a novel framework for fast packet I/O,** Usenix ATC'12, Boston, June 2012
  * Luigi Rizzo, **Revisiting network I/O APIs: the netmap framework,** Communications of the ACM 55 (3), 45-51, March 2012 (a version of this paper appears on ACM Queue)



