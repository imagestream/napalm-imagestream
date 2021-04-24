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
        facts = dict()

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
        interfaces = dict()

        output = self.device.send_command('ubus list network.interface.*')

        for line in output.splitlines():
            interface = {}
            status = self.device.send_command('ubus call ' + line + ' status')
            status_json = json.loads(status)

            # Gives us the interface name 
            interface_name = line.split('.')[2]

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

                    # since we have the kernel device we can get detailed stats from netifd
                    dev_status = self.device.send_command('ubus call network.device status \'{ "name": "' + kernel_dev + '" }\'')
                    dev_status_json = json.loads(dev_status)

                    if "mtu" in dev_status_json:
                        interface['mtu'] = dev_status_json['mtu']
                    
                    if "macaddr" in dev_status_json:    
                        interface['mac_address'] = dev_status_json['macaddr'].upper()
                    
                    if "speed" in dev_status_json:
                        s = re.findall('^[ 0-9]+', dev_status_json['speed'])
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
        
        for arp in v4_neigh.splitlines():
            arp_entry = arp.split()
            if len(arp_entry) > 0:
                ipv4 = arp_entry[0]
                linux_dev = arp_entry[2]
                if "INCOMPLETE" in arp_entry or "FAILED" in arp_entry:
                    mac_address = "00:00:00:00:00:00"
                else:
                    mac_address = arp_entry[4]

                for line in raw_interfaces.splitlines():
                    interface_name = line.split('.')[2]

                    status = self.device.send_command('ubus call ' + line + ' status')
                    status_json = json.loads(status)

                    if "l3_device" in status_json or "device" in status_json: 
                        if "l3_device" in status_json:
                            kernel_dev = status_json['l3_device']
                        else:
                            kernel_dev = status_json['device']
                    else: # We don't seem to have a Linux device for this Oputia device: this shouldn't happen but bail if it does
                        continue  

                    # check if our Opuntia protocol is dhcpv6. If so we won't return anything for this Interface
                    # This check removes most situations where more than one Opuntia / OpenWrt Interface is bound 
                    # a single base linux device.
                    if status_json['proto'] == "dhcpv6":
                        continue
                    # We now check if the Opuntia / Openwrt interface is the same as the linux interface
                    # Linux doesn't keep ages so always set that to 0. 
                    if kernel_dev in linux_dev:
                        arp_dict = dict()
                        arp_dict['interface'] = interface_name
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
        
        for arp in v6_neigh.splitlines():
            arp_entry = arp.split()
            if len(arp_entry) > 0:
                ipv6 = arp_entry[0]
                linux_dev = arp_entry[2]
                if "INCOMPLETE" in arp_entry or "FAILED" in arp_entry:
                    mac_address = "00:00:00:00:00:00"
                else:
                    mac_address = arp_entry[4]

                for line in raw_interfaces.splitlines():
                    interface_name = line.split('.')[2]

                    status = self.device.send_command('ubus call ' + line + ' status')
                    status_json = json.loads(status)

                    if "l3_device" in status_json or "device" in status_json: 
                        if "l3_device" in status_json:
                            kernel_dev = status_json['l3_device']
                        else:
                            kernel_dev = status_json['device']
                    else: # We don't seem to have a Linux device for this Oputia device: this shouldn't happen but bail if it does
                        continue  

                    # check if our Opuntia protocol is dhcp. If so we won't return anything for this Interface
                    # This check removes most situations where more than one Opuntia / OpenWrt Interface is bound 
                    # a single base linux device.
                    if status_json['proto'] == "dhcp":
                        continue
                    # We now check if the Opuntia / Openwrt interface is the same as the linux interface
                    # Linux doesn't keep ages so always set that to 0. 
                    if kernel_dev in linux_dev:
                        arp_dict = dict()
                        arp_dict['interface'] = interface_name
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
        interfaces_proto = dict()

        raw_interfaces = self.device.send_command('ubus list network.interface.*')
        for line in raw_interfaces.splitlines():
            interface_name = line.split('.')[2]

            status = self.device.send_command('ubus call ' + line + ' status')
            status_json = json.loads(status)

            if "proto" in status_json:
                interfaces_proto[interface_name] = status_json['proto']

        return interfaces_proto


    def get_interfaces_ip(self):
        return True



    def get_interfaces_counters(self):
         

        return True   
