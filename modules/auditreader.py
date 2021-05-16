import configparser
import pandas as pd


def open_audit(audit_file):
    return pd.read_csv(audit_file)


class ReadLogs:

    def __init__(self):
        # Read from config.ini to import our Audit log file, user and commands to alert on
        config = configparser.ConfigParser()
        config.read("/app/config.ini")
        # Set our audit file
        audit_file = config.get("auditfile", "file")
        # Set our user we want to alert on
        self.username = config.get("behaviours", "username")
        # Set the list of suspicious commands
        self.cmds = config.get("behaviours", "cmds")
        # Set our pandas output settings
        pd.set_option('display.max_rows', None)
        pd.set_option('display.max_columns', None)
        pd.set_option('display.width', None)
        pd.set_option('display.max_colwidth', None)
        # Open Audit file with pandas to create a dataframe
        self.df = open_audit(audit_file)

    def suspicious_commands(self):
        # Return a dataframe based on username and suspicious commands
        return self.df[(self.df['proctitle'].str.match(self.cmds)== True)
                       & (self.df['username'] == self.username)]

    def root_events(self, data_frame=None):
        # Validate we have a dataframe
        if data_frame is not None:
            # Return our provided dataframe that only contains events with the auid of our username and the euid of root
            return data_frame[(data_frame['auid'] == 1000) & (data_frame['euid'] == 0)]
        else:
            # Return our main dataframe that only contains events with the auid of our username and the euid of root
            return self.df[(self.df['auid'] == 1000) & (self.df['euid'] == 0)]
