Network Process Monitor
_______________________

Network Process Monitor makes it easy for Python developers to monitor a proccess' network usage.

Currently, it works with IPv4 and tested against Python 2.7.

`Development site <https://github.com/Diblo/netprocmon>`__.

© Network Process Monitor contributors 2019 under the `The GNU General Public License v3.0 <https://github.com/Diblo/netprocmon/blob/master/LICENSE.txt>`__.

Installation
-----------------------------

Install using `pip <http://www.pip-installer.org/en/latest/>`__ with:

    pip install netprocmon

Or, `download a wheel or source archive from PyPI <https://pypi.python.org/pypi/netprocmon>`__.

Basic
-----------------------------

    >>> import time
    >>> from netprocmon import Monitor
    >>> pid = 586
    >>> with Monitor() as a:
    ...      a.add_pid(pid)
    ...      a.start()
    ...      while True:
    ...          time.sleep(5)
    ...          print [str(n) for n in a.get_count_by_pid(pid)]
    ...
    ['NetworkTraffic(interface=eth1, recv=2302, pid=586, send=6806)']
    ['NetworkTraffic(interface=eth1, recv=2832, pid=586, send=9104)']
    ['NetworkTraffic(interface=eth1, recv=3548, pid=586, send=10742)', 'NetworkTraffic(interface=eth2, recv=0, pid=586, send=121)']


Listen address/interface
-----------------------------

Limit listening to an interface by providing the interface address

    >>> import time
    >>> from netprocmon import Monitor
    >>> pid = 586
    >>> with Monitor() as a:
    ...      a.add_pid(pid)
    ...      a.add_address("10.0.0.21")
    ...      a.start()
    ...      while True:
    ...          time.sleep(5)
    ...          print [str(n) for n in a.get_count_by_pid(pid)]
    ...
    ['NetworkTraffic(interface=eth1, recv=530, pid=586, send=2758)']
    ['NetworkTraffic(interface=eth1, recv=1538, pid=586, send=5044)']
    ['NetworkTraffic(interface=eth1, recv=2386, pid=586, send=8166)']


Available constants and methods
---------------------------------

=========
Constants
=========
- **P_TCP**: Define the TCP protocol number
- **P_UDP**: Define the UDP protocol number

======================
Process Identification
======================
- **add_pid(PID)**:                 Add a process identification to have the traffic counted
- **remove_pid(PID)**:              Remove a process identification and the traffic count
- **get_pids()**:                   Get a list of process identifications that get the traffic counted
- **get_pid_by_port(proto, port)**: Get the process identification based on a supervise port
- **clear_pids()**:                 Remove all process identifications

=========
Listening
=========
- **add_address(addr)**:    Add a listen address; It should fit with an interface
- **get_addresses()**:      Get all listen addresses
- **remove_address(addr)**: Remove a listen address
- **clear_addresses()**:    Remove all listen addresses

===
Run
===
- **start()**: Start the monitor

============
Traffic Info
============
- **get_count_by_pid(PID)**: Get network traffic based on a process identification

=========
Port Info
=========
- **get_ports_by_pid(PID)**:     Get a list of supervise ports based on a process identification
- **get_ports_by_proto(proto)**: Get a list of supervise ports based on TCP or UDP protocol; See P_TCP, P_UDP
- **get_ports()**:               Get a list of all supervise ports

==============
Interface Info
==============
- **get_interface_by_addr(addr)**:    Return interface name based on addresses
- **get_interface_addrs()**:          Return all interface addresses
- **get_addrs_by_interface(ifName)**: Return addresses based on interface name
