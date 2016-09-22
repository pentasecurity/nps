NPS
======

[PentaSecurity](https://pentasecurity.com) tcp/ip packet simulator.


## Description
NPS(Network Packet Simulator) is tcp/ip packet testing tool.

* Useful that validation inline(or transparent) network appliance.
* Useful that tcp/ip function of server.
* Support packet sender and reflector by TC of xml base.
* Only support TCP/IP protocol.


```
[NPS(Client)] ==> [Server]
[           ] <== [      ]
```

```
[NPS(Client)] ==> [Inline             ]
[   (Server)] <== [  network appliance]
```

```
[NPS(Client)] ==> [Inline             ] ==> [Server]
[           ] <== [  network appliance] <== [      ]
```



## Requirement
    * python 2.6, 2.7
    * scapy 2.1.0


## Installation
To install nps, simply:

    $ apt-get install python-pip
    $ pip install nps

## Quick Start

	$ mkdir -p /opt/penta/nps/script/
    $ cd /opt/penta/nps/script/


connection.xml : write tcp connection packet info
```
<tc name="connection">

<client>
 <packet>
  <action>send</action>
   <include>common</include>
   <step>connection_open</step>
   <flag>syn</flag>
   <mss>1460</mss>
   <seq>0</seq>
   <ack>0</ack>
   <sackPerm>true</sackPerm>
 </packet>

 <packet>
  <action>recv</action>
   <include>common</include>
   <step>connection_open</step>
   <flag>syn+ack</flag>
   <mss>1460</mss>
   <seq>0</seq>
   <ack>1</ack>
   <sackPerm>true</sackPerm>
 </packet>

 <packet>
  <action>send</action>
  <include>common</include>
  <step>connection_open</step>
  <flag>ack</flag>
  <seq>1</seq>
  <ack>1</ack>
 </packet>
</client>

</tc>
```


	$ mkdir -p /opt/penta/nps/script/include
    $ cd /opt/penta/nps/script/include


common.xml : write client interface name and client ip/port and server ip/port
```
<object>
 <clientInt>eth0</clientInt>
 <clientIp>192.168.0.100</clientIp>
 <serverIp>192.168.0.200</serverIp>
 <clientPort>12345</clientPort>
 <serverPort>80</serverPort>
</object>
```

run script

    $ nps -f connection.xml

