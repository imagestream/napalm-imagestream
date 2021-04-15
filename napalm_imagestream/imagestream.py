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
# ImageStream specific changes added by Joshua Snyder.

"""
Napalm driver for ImageStream Oputia.

Read https://napalm.readthedocs.io for more information.
"""

import json

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

    def open(self):
        try:
            self.device = ConnectHandler(device_type='linux',
                                         host=self.hostname,
                                         username=self.username,
                                         password=self.password)
        
        except NetMikoTimeoutException:
            raise ConnectionException('Cannot connect to {}'.format((self.hostname)))


    def close(self):
        self.device.disconnect()

    def get_config(self):
        output = self.device.send_command('ubus call system board')    

        return output

    def is_alive(self):
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        } 

    def get_facts(self):     
        facts = dict()

        uptime = net_connect.send_command('awk \'{print $1}\' /proc/uptime')

        facts['uptime'] = uptime

        hardwareinfo = net_connect.send_command(' ubus call imagestream hardwareinfo')
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
            facts['model']  = hardwareinfo_json['product_id']
    
        if 'serial_number' not in facts:
            facts['serial_number'] = '00000000' 

        """ The system board call will give us the missing system values """
        output = net_connect.send_command('ubus call system board')
        output_json = json.loads(output)

        facts['fqdn'] = output_json['hostname']
        facts['hostname'] = output_json['hostname'].split('.')[0]
        facts['os_version'] = output_json['release']['version'] + " " + output_json['release']['revision']
        if 'vendor' not in facts:
            facts['vendor'] = output_json['release']['manufacturer']

        """ 
        Get the Opuntia / Openwrt Interface list  
        Note. This is the list of interfaces configured in the uci system and not the Linux interfaces that 
        might be present at the kernel level. 
        """
        output = net_connect.send_command('ubus list network.interface.*')

        interface_list = list()

        for line in output.splitlines():
            interface_list.append((line.split('.')[2]))

        facts['interface_list'] = interface_list

        return facts


