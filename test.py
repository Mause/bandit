# -*- coding:utf-8 -*-
#
# Copyright (C) 2018 [Victor Torre](https://github.com/ehooo)
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
import sys
import json
from functools import wraps
from io import StringIO
from io import BytesIO
from unittest import main
from unittest import TestCase
from textwrap import dedent

from bandit.core.config import BanditConfig
from bandit.core.manager import BanditManager


def run_for(source):
    config = BanditConfig()

    manager = BanditManager(config=config, agg_type='vuln')
    manager._parse_file('-', BytesIO(source.encode('utf-8')), ['-'])

    return [issue.as_dict() for issue in manager.get_issue_list()]


def example_file(filename):
    def first(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with open(filename) as fh:
                return func(*args, run_for(fh.read()), **kwargs)
        return wrapper
    return first


def example(source):
    def first(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, run_for(dedent(source)), **kwargs)
        return wrapper
    return first


class TestThing(TestCase):
    @example('''
    import paramiko
    paramiko.exec_command('something; really; unsafe')
    ''')
    def test_it(self, results):
        self.assertEqual(len(results), 1)

    @example_file(f'examples/paramiko_injection.py')
    def test_paramiko_injection(self, results):
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['test_id'], 'B601')
        self.assertEqual(results[1]['test_id'], 'B601')


if __name__ == '__main__':
    main()
