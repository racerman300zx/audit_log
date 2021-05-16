from unittest import TestCase, main as unittest_main
from modules.auditreader import ReadLogs
import pandas as pd
import numpy as np


class TestAuditReader(TestCase):

    @classmethod
    def setUpClass(cls):
        # Create our global calling the Class
        cls.testclass = ReadLogs()

    @classmethod
    def dataframe(cls):
        # Create class method to return our sample dataframe
        data = {"id": [np.int64("1927")],
                "event_timestamp": ["2019-06-06 16:18:58+00"],
                "proctitle": ["curl --fail -sSl http%3A//169.254.169.254/latest/meta-data/placement/availability-zone"],
                "username": ["root"],
                "exit": [np.int64("0")],
                "ppid": [np.int64("21831")],
                "pid": [np.int64("21832")],
                "auid": [np.int64("4294967295")],
                "uid": [np.int64("0")],
                "gid": [np.int64("0")],
                "euid": [np.int64("0")],
                "suid": [np.int64("0")],
                "fsuid": [np.int64("0")],
                "egid": [np.int64("0")],
                "sgid": [np.int64("0")],
                "fsgid": [np.int64("0")]}
        return pd.DataFrame(data)

    def test_open_audit(self):
        # Test our sample dataframe against dataframe pulled from csv file
        pd.testing.assert_frame_equal(self.testclass.df, self.dataframe())

    def test_suspicious_commands(self):
        # Test our sample dataframe against dataframe pulled from csv file
        pd.testing.assert_frame_equal(self.testclass.suspicious_commands(), self.dataframe())

    def test_root_events(self):
        # Test our sample dataframe against the csv dataframe
        try:
            pd.testing.assert_frame_equal(self.testclass.root_events(), self.dataframe())
        except AssertionError:
            # Dataframes are not equal
            pass
        else:
            # Dataframes are equal
            raise AssertionError


if __name__ == '__main__':
    unittest_main()
