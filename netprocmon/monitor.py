#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is copied from Network Process Monitor.
#
# Network Process Monitor is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Network Process Monitor is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Printrun.  If not, see <http://www.gnu.org/licenses/>.

import struct
import socket
import psutil
import time
import threading
import logging

D_SEND = "send" # Define the send name
D_RECV = "recv" # Define the receive name

P_TCP = 6  # Define the TCP protocol number
P_UDP = 17 # Define the UDP protocol number

class _ReadOnlyClass(object):
    """ A main class to make a class non-writable.
        It is used by classes to be returned. """
    __slots__ = ('__dict__',)

    def __setattr__(self, n, v):
        if self.__dict__.get(n, None) is None:
           self.__dict__[n] = v

    def __delattr__(self, n):
        pass

    def __str__(self):
        def format_values():
            for n, v in self.__dict__.iteritems():
                if not n[0] == "_" and (isinstance(v, int) or isinstance(v, basestring)):
                    yield "%s=%s" %(n, v)

        return "%s(%s)" %(self.__class__.__name__, ", ".join(format_values()))

class Interface(_ReadOnlyClass):
    """ A class to hold on port information """
    __slots__ = ('interface', 'address', 'family')

    interface = None
    address = None
    family = None
    def __init__(self, interface, address, family=socket.AF_INET):
        self.interface = interface
        self.address = address
        self.family = family

class port(_ReadOnlyClass):
    """ A class to hold on port information """
    __slots__ = ('pid', 'family', 'proto', 'port')

    pid = None
    proto = None
    port = None
    family = None
    def __init__(self, pid, proto, port, family=socket.AF_INET):
        self.pid = pid
        self.proto = proto
        self.port = port
        self.family = family

class NetworkTraffic(_ReadOnlyClass):
    """ A class to hold on network traffic information """
    __slots__ = ('pid', 'interface', 'send', 'recv')

    pid = None
    interface = None
    send = None
    recv = None
    def __init__(self, pid, interface, send, recv):
        self.pid = pid
        self.interface = interface
        self.send = send
        self.recv = recv


class _PacketSniffer(threading.Thread):
    __slots__ = ('_monitor', '_count')

    _monitor = None
    _count = {}

    def __init__(self, monitor, count):
        self._monitor = monitor
        self._count = count

        # Thread
        super(_PacketSniffer, self).__init__()
        self.daemon = False
        self.stop = threading.Event()
        self.start()

    def run(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            while not self.stop.is_set():
                # Receive a package
                packet = s.recvfrom(65565)[0] # It is in a tuple

                # Parse package
                # Todo: Support WLAN
                #
                # See:
                #  * https://elearning.vector.com/pluginfile.php/266/mod_page/content/7/IP_4.2_GRA_EthernetPacket_EN.png
                #  * https://nmap.org/book/tcpip-ref.html
                try:
                    hInfo = struct.unpack('!HBBHHHBBH4s4sHH', packet[12:38])
                    """
                      - Ethernet Frame -
                           hInfo[0]  = Ethertype
                      - IPv4 header -
                           hInfo[1]  = Version & Internet Header Length
                           hInfo[2]  = Type Of Service
                           hInfo[3]  = Total Length
                           hInfo[4]  = Indentation
                           hInfo[5]  = Ip Flags & Fragment Offset
                           hInfo[6]  = Time To Live
                           hInfo[7]  = Protocol
                           hInfo[8]  = Header Checksum
                           hInfo[9]  = Source Address
                           hInfo[10] = Destination Address
                      - TCP or UDP header -
                           hInfo[11] = Source Port
                           hInfo[12] = Destination Port
                    """
                except struct.error:
                    continue

                # Parse TCP or UDP protocol from IP package; Ethertype: IP Protocol number = 8
                if socket.ntohs(hInfo[0]) == 8 and hInfo[7] in [6, 17]:
                    # Send data
                    ifName = self._monitor.get_listen_interface_by_addr(socket.inet_ntoa(hInfo[9]))
                    pid = self._monitor.get_pid_by_port(hInfo[7], hInfo[11])
                    if ifName and pid:
                        self._add_count(pid, ifName, D_SEND, len(packet))
                        continue

                    # Receiv data
                    ifName = self._monitor.get_listen_interface_by_addr(socket.inet_ntoa(hInfo[10]))
                    pid = self._monitor.get_pid_by_port(hInfo[7], hInfo[12])
                    if ifName and pid:
                        self._add_count(pid, ifName, D_RECV, len(packet))
                        continue

                # Take a break if we don't have any ports or addresses that we listen to
                while not self.stop.is_set() and \
                      (not self._monitor.get_ports() or \
                       not self._monitor.get_listen_addrs()):
                    time.sleep(1)
        except:
            logging.exception("_PacketSniffer:run:error")
            self.stop.set()

    def _add_count(self, pid, ifName, direction, size):
        """ A method to make the code clearer """
        try:
            self._count.setdefault(pid, {}).setdefault(ifName, {})[direction] += size
        except KeyError:
            self._count.setdefault(pid, {}).setdefault(ifName, {}).setdefault(direction, size)

    def close(self):
        self.stop.set()

    __del__ = close

class Monitor(threading.Thread):
    __slots__ = ('_packetSniffer', '_listen_addrs', '_listen_ports', '_addrs_if', '_count')

    _packetSniffer = None
    _listen_addrs = []
    _listen_ports = {}
    _addrs_if = {}
    _count = {}

    def __init__(self):
        self._addrs_if = self._import_interfaces()

        # Thread
        super(Monitor, self).__init__()
        self.daemon = False
        self.stop = threading.Event()


    """ Process identification methods """
    def add_pid(self, PID):
        """ Add a process identification to have the traffic counted """
        if not self._listen_ports.get(PID, None):
            self._listen_ports[PID] = self._import_pid_ports(PID)

    def remove_pid(self, PID):
        """ Remove a process identification and the traffic count """
        if self._listen_ports.get(PID, None):
            self._listen_ports.pop(PID, None)
            self._count.pop(PID, None)

    def get_pids(self):
        """ Get a list of process identifications that get the traffic counted """
        return self._listen_ports.keys()

    def get_pid_by_port(self, proto, port):
        """ Get the process identification based on a supervise port """
        for p in self.get_ports_by_proto(proto):
            if p.port == port:
                return p.pid
        return None

    def clear_pids(self):
        """ Remove all process identifications """
        self._listen_ports = {}
        self._count = {}


    """ Listening methods """
    def add_address(self, addr):
        """ Add a listening restriction; The address should
            fit with an interface address """
        if not addr in self._listen_addrs:
            self._listen_addrs.append(addr)

    def get_addresses(self):
        """ Return a list of listening restrictions """
        return self._listen_addrs

    def remove_address(self, addr):
        """ Remove a listening restriction """
        if addr in self._listen_addrs:
            self._listen_addrs.remove(addr)

    def clear_addresses(self):
        """ Remove all listening restriction """
        self._listen_addrs = []

    def get_listen_addrs(self):
        """ Return a list of interface addresses
            that are being listed to """
        return self._addrs_if.keys()

    def get_listen_interfaces(self):
        """ Return a list of interfaces and with their
            addresses that are being listed to """
        return [Interface(ifName, self._addrs_if[ifName]) for ifName in self._addrs_if]

    def get_listen_interface_by_addr(self, addr):
        """ Return the interface name based on a address; If the
            address is not listened to, None will be returned """
        return self._addrs_if.get(addr, None)

    def _import_interfaces(self):
        """ Create a list of inetrface addresses """
        addrs_if = {}
        NICConfig = psutil.net_if_addrs()
        for ifName in NICConfig:
            for ifconfig in NICConfig[ifName]:
                if ifconfig.family == socket.AF_INET and \
                   (not self._listen_addrs or ifconfig.address in self._listen_addrs):
                    addrs_if[ifconfig.address] = ifName
        return addrs_if


    """ Run method """
    def start(self):
        """ Start monitor """
        if not self._packetSniffer:
            super(Monitor, self).start()
            self._packetSniffer = _PacketSniffer(self, self._count)


    """ Count methods (Only info methods) """
    def get_count_by_pid(self, PID):
        """ Get network traffic based on a process identification """
        traffic = []
        count = self._count.get(PID, {}).copy()
        for ifName in count:
            traffic.append(
                NetworkTraffic(PID,
                            ifName,
                            count[ifName].get(D_SEND, 0),
                            count[ifName].get(D_RECV, 0)))
        return traffic


    """ Port methods (Only info methods are public) """
    def get_ports_by_pid(self, PID):
        """ Get a list of supervise ports based on a process identifiers """
        return self._listen_ports.get(PID, [])

    def get_ports_by_proto(self, proto):
        """ Get a list of supervise ports based on TCP or UDP protocol; P_TCP, P_UDP """
        return [p for p in self.get_ports() if p.proto == proto]

    def get_ports(self):
        """ Get a list of all supervise ports """
        ports = []
        for p in self._listen_ports.values():
            ports.extend(p)
        return ports

    def _import_pid_ports(self, PID):
        """ Create a list of ports that a process uses """

        old_ports = self.get_ports_by_pid(PID)
        def isPortKnown(port):
            for p in old_ports:
                if p.proto == port.proto and p.port == port.port:
                    return p
            return port

        def getPorts(obj):
            for con in obj.connections('tcp4'):
                yield isPortKnown(port(PID, P_TCP, con.laddr.port))
            for con in obj.connections('udp4'):
                yield isPortKnown(port(PID, P_UDP, con.laddr.port))

        process = psutil.Process(PID)
        listen_ports = list(getPorts(process))
        for child in process.children(recursive=True):
            listen_ports.extend(getPorts(child))

        return listen_ports


    """ Thread methods """
    def __enter__(self):
        return self

    def run(self):
        """ This method is used to keep interface addresses
            and ports up to date """
        try:
            while not self.stop.is_set():
                self._addrs_if = self._import_interfaces()

                for PID in self.get_pids():
                    self._listen_ports[PID] = self._import_pid_ports(PID)

                time.sleep(1)
        except:
            logging.exception("Monitor:run:error")
            self.stop.set()

    def close(self):
        if self._packetSniffer:
            self._packetSniffer.close()
        if hasattr(self, 'stop'):
            self.stop.set()

    def __exit__(self, *exc_info):
        self.close()
        return not exc_info[0]

    __del__ = close
