from unittest import TestCase, main as unittest_main
from detector import create_alert
import pandas as pd
import numpy as np


class TestDetector(TestCase):
    # Create class method to return our sample dataframe
    @classmethod
    def dataframe(cls):
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

    def test_create_alert(self):
        # Create our sample dataframe
        sample_dataframe = self.dataframe()
        row = 0
        # Create our test message with content pulled from the sample dataframe
        test_text = (f'---Suspicious Root process identified---\nProcess: {sample_dataframe["proctitle"][row]}\n'
                     f'Username: {sample_dataframe["username"][row]}\n'
                     f'Time: {sample_dataframe["event_timestamp"][row]}\nPID: {sample_dataframe["pid"][row]}\n'
                     f'AUID: {sample_dataframe["auid"][row]}\n'
                     f'UID: {sample_dataframe["uid"][row]}\nEUID: {sample_dataframe["euid"][row]}\n')
        # Capture the logging method output from our method
        with self.assertLogs() as captured:
            # Call our method to test the logging
            create_alert(sample_dataframe)
        # Test that we are returning 1 record
        self.assertEqual(len(captured.records), 1)
        # Test the that logging output matches our test text
        self.assertEqual(captured.records[0].getMessage(), test_text)


if __name__ == '__main__':
    unittest_main()
