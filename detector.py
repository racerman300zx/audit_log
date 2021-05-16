from modules.auditreader import ReadLogs
import logging
import sys
import numpy as np


def create_alert(data_frame):
    # Set our logging to output to STDOUT
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(message)s')
    # To prevent too many alerts, only create alerts for processes with less then 10 executions
    minimized_df = data_frame[data_frame.groupby('proctitle')['proctitle'].transform('size') < 10]
    for row in minimized_df.index:
        # Validate if the uid was root. The uid field records the user ID of the user who started the analyzed process.
        if minimized_df["uid"][row] == np.int64(0):
            suspicious_text = 'Suspicious Root'
        else:
            suspicious_text = 'Suspicious'
        # Send our findings to STDOUT
        logging.info(f'---{suspicious_text} process identified---\nProcess: {minimized_df["proctitle"][row]}\n'
                     f'Username: {minimized_df["username"][row]}\n'
                     f'Time: {minimized_df["event_timestamp"][row]}\nPID: {minimized_df["pid"][row]}\n'
                     f'AUID: {minimized_df["auid"][row]}\n'
                     f'UID: {minimized_df["uid"][row]}\nEUID: {minimized_df["euid"][row]}\n')


if __name__ == "__main__":
    # Call our class
    AuditRead = ReadLogs()
    # Get a dataframe with our suspicious processes
    user_logs = AuditRead.suspicious_commands()
    # Send the dataframe containing our suspicious commands to our STDOUT
    create_alert(user_logs)



