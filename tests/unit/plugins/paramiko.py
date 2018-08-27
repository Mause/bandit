# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from tests.unit.plugins import example
from tests.unit.plugins import example_file

from unittest import TestCase


class TestThing(TestCase):
    @example('''
    import paramiko
    paramiko.exec_command('something; really; unsafe')
    ''')
    def test_it(self, results):
        self.assertEqual(len(results), 1)

    @example_file('examples/paramiko_injection.py')
    def test_paramiko_injection(self, results):
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['test_id'], 'B601')
        self.assertEqual(results[1]['test_id'], 'B601')
