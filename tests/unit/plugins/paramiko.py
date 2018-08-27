import bandit

from . import example
from . import example_file

from unittest import TestCase

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