#!/usr/bin/python
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

from netprocmon import Monitor, P_TCP, P_UDP
import psutil

with Monitor() as m:

    print '""" Process Identification """'
    i = 0
    for proc in psutil.process_iter():
        m.add_pid(proc.pid)
        m.add_pid(proc.pid)
        i += 1
    if len(m.get_pids()) != i:
        raise
    for proc in psutil.process_iter():
        m.remove_pid(proc.pid)
        i -= 1
        break
    if len(m.get_pids()) != i:
        raise
    m.clear_pids()
    if len(m.get_pids()) != 0:
        raise

    print
    print '""" Run """'
    for proc in psutil.process_iter():
        m.add_pid(proc.pid)
    m.start()

    print
    print '""" Listening """'
    m.add_address("10.0.0.1")
    m.add_address("127.0.0.1")
    if len(m.get_addresses()) != 2:
        raise
    m.remove_address("127.0.0.1")
    if len(m.get_addresses()) != 1:
        raise
    m.clear_addresses()
    if len(m.get_addresses()) != 0:
        raise
    print m.get_addresses()

    print
    print '""" Interface Info """'
    print m.get_interface_by_addr("127.0.0.1")
    print m.get_interface_addrs()
    print m.get_addrs_by_interface('eth1')

    print
    print '""" Port Info """'
    for pid in m.get_pids():
        print str(pid) + " : " + str([str(p) for p in m.get_ports_by_pid(pid)])
    print
    print m.get_pid_by_port(P_TCP, 1000)
    print m.get_pid_by_port(P_UDP, 1000)
    print
    print [str(port) for port in m.get_ports_by_proto(P_TCP)]
    print
    print [str(port) for port in m.get_ports_by_proto(P_UDP)]
    print
    print [str(port) for port in m.get_ports()]

    print
    print '""" Count Info """'
    for pid in m.get_pids():
        print str(pid) + " : " + str([str(t) for t in m.get_count_by_pid(pid)])
    print

