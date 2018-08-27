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

from functools import wraps
from io import BytesIO
from textwrap import dedent

from bandit.core.config import BanditConfig
from bandit.core.manager import BanditManager


def run_bandit_over_source_string(source):
    '''Run's Bandit against the given source

    This method uses the same approach as the CLI for Bandit when processing
    input from stdin.
    '''
    config = BanditConfig()

    manager = BanditManager(config=config, agg_type='vuln')
    manager._parse_file('-', BytesIO(source.encode('utf-8')), ['-'])

    return [issue.as_dict() for issue in manager.get_issue_list()]


def example_file(filename):
    'Decorator which is used to execute bandit tests against a specified file'
    def first(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            with open(filename) as fh:
                return func(
                    self,
                    run_bandit_over_source_string(fh.read()),
                    *args, **kwargs
                )
        return wrapper
    return first


def example(source):
    'Decorator which is used to execute bandit tests against a string.'
    def first(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            return func(
                self,
                run_bandit_over_source_string(dedent(source)),
                *args, **kwargs
            )
        return wrapper
    return first
