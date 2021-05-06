# -*- coding: utf-8 -*-
# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#
# Opuntia specific changes added by Joshua Snyder.

"""
Napalm driver for ImageStream Oputia / OpenWrt.

Read https://napalm.readthedocs.io for more information.
"""

import json
import re

from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
from napalm.base import NetworkDriver
from napalm.base.exceptions import (
    ConnectionException,
    SessionLockedException,
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
)


class ImageStreamDriver(NetworkDriver):
    """Napalm driver for ImageStream."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        netmiko_argument_map = {
            'port': None,
            'verbose': False,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
            'secret': password,
            'allow_agent': False,
            'fast_cli': True
        }

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {
                k: optional_args.get(k, v)
                for k, v in netmiko_argument_map.items()
            }
        self.port = optional_args.get('port', 22)
        self.sudo_pwd = optional_args.get('sudo_pwd', self.password)
        self.fast_cli = optional_args.get('fast_cli', True )



    def open(self):
        try:
            self.device = ConnectHandler(device_type='linux',
                                         host=self.hostname,
                                         username=self.username,
                                         password=self.password,
                                         fast_cli=True)
        
        except NetMikoTimeoutException:
            raise ConnectionException('Cannot connect to {}'.format((self.hostname)))


    def close(self):
        self.device.disconnect()

    def get_config(self):
        output = self.device.send_command('uci show')    

        return output

    def is_alive(self):
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        } 

    # Opuntia / Openwrt may not have values for some items here we fill in keys that aren't already present
    # I kinda hate this... But I don't see any other choice. 
    def _interfaceFillValues(self, interface):
        # if we don't have an interface status set it down
        if "is_up" not in interface:
            interface['is_up'] = False
        # if we don't have an interface enabled set it down    
        if "is_enabled" not in interface:
            interface['is_enabled'] = False
        # Opuntia / Openwrt does not have an interface description field so this will always fill in. 
        if "description" not in interface:
            interface['description'] = ''
        # If we don't have an last_flapped set it to -1 
        if "last_flapped" not in interface:
            interface['last_flapped'] = -1.0
        # Virtual interfaces and bridge interfaces don't really have a speed. So set it to null if we get here. 
        if "speed" not in interface:
            interface['speed'] = ''
        # If mtu is not present fill it in. Should only happen if the interface is admin down.
        if "mtu" not in interface:
            interface['mtu'] = ''
        # Non-Ethernet devices may not have a mac address, VPN interfaces for example. 
        if "mac_address" not in interface:
            interface['mac_address'] = ''

        return interface                      

    def get_facts(self):     
        facts = {}

        uptime = self.device.send_command('awk \'{print $1}\' /proc/uptime')

        facts['uptime'] = uptime

        hardwareinfo = self.device.send_command('ubus call imagestream hardwareinfo')
        """ 
        Check to see if the hardwareinfo ubus call failed. 
        This can fail if we have an old system, are running in a vm 
        or this is a non-ImageStream openwrt device. If it worked, we will use the 
        hardwareinfo values otherwise we will have to fake a serial number. 
        """
        if "Command failed" not in hardwareinfo:
            hardwareinfo_json = json.loads(hardwareinfo)
            facts['serial_number'] = hardwareinfo_json['serial_number']
            facts['vendor'] = 'ImageStream Internet Solutions'
            facts['model']  = hardwareinfo_json['product_id'] + " v" + hardwareinfo_json['product_rev']
    
        if 'serial_number' not in facts:
            facts['serial_number'] = '00000000' 

        """ The system board call will give us the missing system values """
        output = self.device.send_command('ubus call system board')
        output_json = json.loads(output)

        facts['fqdn'] = output_json['hostname']
        facts['hostname'] = output_json['hostname'].split('.')[0]
        facts['os_version'] = output_json['release']['version'] + " " + output_json['release']['revision']
        # If we didn't get the vendor or model number from the new hardwareinfo call, get it from the release file
        # this isn't as good of source for this info
        if 'vendor' not in facts:
            facts['vendor'] = output_json['release']['manufacturer']
        if 'model' not in facts:
            facts['model'] = output_json['release']['product'] + " v" + output_json['release']['hwrev']


        """ 
        Get the Opuntia / Openwrt Interface list  
        Note. This is the list of interfaces configured in the uci system and not 
        the Linux interfaces that might be present at the Linux kernel level. 
        """
        output = self.device.send_command('ubus list network.interface.*')

        interface_list = list()

        for line in output.splitlines():
            interface_list.append((line.split('.')[2]))

        facts['interface_list'] = interface_list

        return facts

    def get_interfaces(self):
        interfaces = {}

        output = self.device.send_command('ubus list network.interface.*')

        # This gets us ALL of the interface stats at the linux level for all devices
        dev_status = self.device.send_command('ubus call network.device status \' { "none" : "none" } \'')
        dev_status_json = json.loads(dev_status)

        for line in output.splitlines():
            interface = {}
            # Gives us the interface name 
            interface_name = line.split('.')[2]

            status = self.device.send_command('ubus call ' + line + ' status')
            status_json = json.loads(status)

            # Check a few basic items and set them if present
            if "up" in status_json:
                interface['is_up'] = status_json['up']
            if "autostart" in status_json:
                interface['is_enabled'] = status_json['autostart'] 
            if "uptime" in status_json:
                interface['last_flapped'] = status_json['uptime']      

            #Check the interface is really there and it has a single linux device, ie. it's not a bridge 
            if status_json['available'] is True:
                if "l3_device" in status_json or "device" in status_json: 
                    if "l3_device" in status_json:
                        kernel_dev = status_json['l3_device']
                    else:
                        kernel_dev = status_json['device']    

            if kernel_dev is not None:        
                if "mtu" in dev_status_json[kernel_dev]:
                    interface['mtu'] = dev_status_json[kernel_dev]['mtu']          
                if "macaddr" in dev_status_json[kernel_dev]:    
                    interface['mac_address'] = dev_status_json[kernel_dev]['macaddr'].upper()              
                if "speed" in dev_status_json[kernel_dev]:
                    s = re.findall('^[ 0-9]+', dev_status_json[kernel_dev]['speed'])
                    if s:
                        interface['speed'] = s[0]
                
            interfaces[interface_name] = self._interfaceFillValues(interface)

        return interfaces

    def get_arp_table(self):
        """ 
        This seems simple but due to the way Opuntia / Openwrt has interfaces and Linux Interfaces this 
        complicates the interface that we return for each Linux arp entry. Since it's possible in a few 
        cases to have an Opuntia Interface bind to the same Linux device (Proto Dhcp & Dhcpv6 for example)
        I think it's best to return what is effectivly the same arp Entry for each Opuntia interface if that
        happenes to be the case.  
        """
        arp_table = list()

        # Get the Ipv4 neighbor table
        v4_neigh = self.device.send_command('ip -4 neigh')

        raw_interfaces = self.device.send_command('ubus list network.interface.*')

        """
        Loop through the Opuntia interfaces and determine the kernel device that each one is bound to. 
        We reference this when we create the arp_table. 
        """
        kernel_dev = {}
        for line in raw_interfaces.splitlines():
            interface_name = line.split('.')[2]

            status = self.device.send_command('ubus call ' + line + ' status')
            status_json = json.loads(status)
            
            # check if our Opuntia protocol is dhcpv6. If so we won't return anything for this Interface
            # This check removes most situations where more than one Opuntia / OpenWrt Interface is bound 
            # a single base linux device.
            if status_json['proto'] == "dhcpv6":
                    continue

            if "l3_device" in status_json or "device" in status_json: 
                if "l3_device" in status_json:
                    dev = status_json['l3_device']
                else:
                    dev = status_json['device']

            kernel_dev[interface_name] = dev  
        
        for arp in v4_neigh.splitlines():
            arp_entry = arp.split()
            if len(arp_entry) > 0:
                ipv4 = arp_entry[0]
                linux_dev = arp_entry[2]
                if "INCOMPLETE" in arp_entry or "FAILED" in arp_entry:
                    mac_address = "00:00:00:00:00:00"
                else:
                    mac_address = arp_entry[4]
                
                # We now check if the Opuntia / Openwrt interface is the same as the linux interface
                # Linux doesn't keep ages so always set that to 0. 
                for opunita_dev in kernel_dev:
                    if kernel_dev[opunita_dev] in linux_dev:
                        arp_dict = {}
                        arp_dict['interface'] = opunita_dev
                        arp_dict['mac'] = mac_address.upper()
                        arp_dict['ip'] = ipv4
                        arp_dict['age'] = 0

                        arp_table.append(arp_dict)

        return arp_table    

    def get_ipv6_neighbors_table(self):
        """
        Much like get_arp_table we have the same issue with mapping Opuntia / OpenWrt interfaces to the 
        underlying Linux devices and Arp tables. So we are going to return Interfaces that match and 
        possibily multiple times for a single entry.
        """
        ipv6_neighbors_table = list()
        # Get the Ipv6 neighbor table
        v6_neigh = self.device.send_command('ip -6 neigh')

        raw_interfaces = self.device.send_command('ubus list network.interface.*')
        
        kernel_dev = {}
        for line in raw_interfaces.splitlines():
            interface_name = line.split('.')[2]

            status = self.device.send_command('ubus call ' + line + ' status')
            status_json = json.loads(status)
            
            # check if our Opuntia protocol is dhcp. If so we won't return anything for this Interface 
            # since we are looking for ipv6 neighbor entries. 
            # This check removes most situations where more than one Opuntia / OpenWrt Interface is bound 
            # a single base linux device.
            if status_json['proto'] == "dhcp":
                    continue

            if "l3_device" in status_json or "device" in status_json: 
                if "l3_device" in status_json:
                    dev = status_json['l3_device']
                else:
                    dev = status_json['device']

            kernel_dev[interface_name] = dev  

        for arp in v6_neigh.splitlines():
            arp_entry = arp.split()
            if len(arp_entry) > 0:
                ipv6 = arp_entry[0]
                linux_dev = arp_entry[2]
                if "INCOMPLETE" in arp_entry or "FAILED" in arp_entry:
                    mac_address = "00:00:00:00:00:00"
                else:
                    mac_address = arp_entry[4]

                # We now check if the Opuntia / Openwrt interface is the same as the linux interface
                # Linux doesn't keep ages so always set that to 0. 
                for opunita_dev in kernel_dev:
                    if kernel_dev[opunita_dev] in linux_dev:
                        arp_dict = {}
                        arp_dict['interface'] = opunita_dev
                        arp_dict['mac'] = mac_address.upper()
                        arp_dict['ip'] = ipv6
                        arp_dict['age'] = 0
                        ipv6_neighbors_table.append(arp_dict)

        return ipv6_neighbors_table        

    def _get_interfaces_protocol(self):
        """
        Opuntia intefaces can have many different protocol types so it's useful to be able to get these also
        Hence this private function.
        """
        interfaces_proto = {}

        raw_interfaces = self.device.send_command('ubus list network.interface.*')
        for line in raw_interfaces.splitlines():
            interface_name = line.split('.')[2]

            status = self.device.send_command('ubus call ' + line + ' status')
            status_json = json.loads(status)

            if "proto" in status_json:
                interfaces_proto[interface_name] = status_json['proto']

        return interfaces_proto

    def get_interfaces_ip(self):
        """
        Netifd under Opuntia / OpenWrt tracks addresses in a few different ways. Ipv4 is easy, there is a list of Ipv4 
        addresses and that's that. But Ipv6 it tracks if you have a address set or if you got a prefix assigned to 
        the interface. And confusingly it then refers to the assigned network as "address" and the actuall address as
        "local-address" most of the logic below is to parse this out.  
        """
        interfaces_ip = {}

        raw_interfaces = self.device.send_command('ubus list network.interface.*')
        for line in raw_interfaces.splitlines():
            ipv4 = {}
            ipv6 = {}
        
            interface_name = line.split('.')[2]

            status = self.device.send_command('ubus call ' + line + ' status')
            status_json = json.loads(status)
            
            if "ipv4-address" in status_json.keys() and status_json["ipv4-address"] :
                for i in range(len(status_json["ipv4-address"])):
                    if "address" in status_json["ipv4-address"][i]:
                        ip = {}
                        mask = {}
                        mask["prefix_length"] = status_json["ipv4-address"][i]["mask"]
                        ip[status_json["ipv4-address"][i]["address"]] = mask
                        ipv4.update(ip)

            if "ipv6-address" in status_json.keys() and status_json["ipv6-address"]:
                for i in range(len(status_json["ipv6-address"])):
                    if "address" in status_json["ipv6-address"][i]:
                        ip = {}
                        mask = {}
                        mask["prefix_length"] = status_json["ipv6-address"][i]["mask"]
                        ip[status_json["ipv6-address"][i]["address"]] = mask
                        ipv6.update(ip)
        
            if "ipv6-prefix-assignment" in status_json.keys() and status_json["ipv6-prefix-assignment"]:
                for i in range(len(status_json["ipv6-prefix-assignment"])):
                    if "local-address" in status_json["ipv6-prefix-assignment"][i]:
                        ip = {}
                        mask = {}
                        mask["prefix_length"] = status_json["ipv6-prefix-assignment"][i]["local-address"]["mask"]
                        ip[status_json["ipv6-prefix-assignment"][i]["local-address"]["address"]] = mask
                        ipv6.update(ip)

            interfaces_ip[interface_name] = {}
            interfaces_ip[interface_name]["ipv4"] = {}
            interfaces_ip[interface_name]["ipv6"] = {}
            interfaces_ip[interface_name]["ipv4"].update(ipv4)
            interfaces_ip[interface_name]["ipv6"].update(ipv6)

        return interfaces_ip


    def get_interfaces_counters(self):
        """
        Since the statistics Opuntia / OpenWrt keeps slightly different statistics, I need to map values 
        into the Napalm Schema. Sadly we have alot more data on the Opuntia side but most of it doesn't 
        fit into this schema. And we are lacking info on broadcast packets so...  

        Napalm                              Opuntia / OpenWrt
        tx_errors               :           tx_errors
        rx_errors               :           rx_errors
        tx_discards             :           tx_dropped
        rx_discards             :           rx_dropped
        tx_octets               :           tx_bytes
        rx_octets               :           rx_bytes
        tx_unicast_packets      :           tx_packets
        rx_unicast_packets      :           rx_packets
        tx_muliticast_packets   :           N/A 
        rx_muliticast_packets   :           multicast
        tx_broadcast_packets    :           N/A
        rx_broadcast_packets    :           N/A

        """
        interfaces_counters = {}

        # This gets us ALL of the interface counters at the linux kernal level for all devices
        linux_counters_raw = self.device.send_command('ubus call network.device status \' { "none" : "none" } \'')
        linux_counters = json.loads(linux_counters_raw)

        raw_interfaces = self.device.send_command('ubus list network.interface.*')
        for line in raw_interfaces.splitlines():
            interface_name = line.split('.')[2]

            status = self.device.send_command('ubus call ' + line + ' status')
            status_json = json.loads(status)

            if status_json['available'] is True:
                if "l3_device" in status_json or "device" in status_json: 
                    if "l3_device" in status_json:
                        kernel_dev = status_json['l3_device']
                    else:
                        kernel_dev = status_json['device']   

            if kernel_dev is not None:
                if linux_counters[kernel_dev]["statistics"]:
                    stats = {}
                    stats["tx_errors"] = linux_counters[kernel_dev]["statistics"]["tx_errors"]
                    stats["rx_errors"] = linux_counters[kernel_dev]["statistics"]["rx_errors"]
                    stats["tx_discards"] = linux_counters[kernel_dev]["statistics"]["tx_dropped"]
                    stats["rx_discards"] = linux_counters[kernel_dev]["statistics"]["rx_dropped"]
                    stats["tx_octets"] = linux_counters[kernel_dev]["statistics"]["tx_bytes"]
                    stats["rx_octets"] = linux_counters[kernel_dev]["statistics"]["rx_bytes"]
                    stats["tx_unicast_packets"] = linux_counters[kernel_dev]["statistics"]["tx_packets"]
                    stats["rx_unicast_packets"] = linux_counters[kernel_dev]["statistics"]["rx_packets"]
                    stats["tx_muliticast_packets"] = 0
                    stats["rx_muliticast_packets"] = linux_counters[kernel_dev]["statistics"]["multicast"]
                    stats["tx_broadcast_packets"] = 0
                    stats["rx_broadcast_packets"] = 0
                    interfaces_counters[interface_name] = stats           

        return interfaces_counters

    def load_merge_candidate(self, filename=None, config=None):
        if not filename and not config:
            raise MergeConfigException('filename or config must be provided')
        
        self.loaded = True

        if filename is not None:
            with open(filename, 'r') as f:
                candidate = f.readlines()
        else:
            candidate = config

        if not isinstance(candidate, list):
            candidate = [candidate]

        candidate = [line for line in candidate if line]
        for uci_command in candidate:
            output = self.send_command(uci_command)
            if "error" in output or "not found" in output:
                raise MergeConfigException("Uci Command '{0}' cannot be applied.".format(uci_command))

    def discard_config(self):
        if self.loaded:
            self.send_command('uci revert')        

    def compare_config(self):
        if self.loaded:
            diff = self.send_command('uci changes')
            return diff
        return ''

    def commit_config(self):
        if self.loaded:
            self.send_command('uci commit')
            self.changed = True
            self.loaded = False              