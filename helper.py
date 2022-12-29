import configparser
from pyarrow import flight
import pandas as pd
from datetime import datetime

class Log:
    def __init__(self, file):
        self.logging_file = open(file, 'a+')

    def log_msg(self, msg, _type):
        now = datetime.now()
        dt = now.strftime("%m/%d/%Y %H:%M:%S")
        self.logging_file.write((f"{[_type]} {dt}: {msg} \n"))

    def debug(self, msg):
        self.log_msg(msg, "DEBUG")

    def err(self, msg):
        self.log_msg(msg, "ERROR")

class Helper:
    client = None
    config = None
    options = None
    views = None
    privileges = None
    policies = None
    def __init__(self):
        self.logger = Log("dremio-rbac.log")
    def parse_config(self, conf_file, required):
        config = configparser.ConfigParser()
        config.read(conf_file)
        conf = config['default']
        # validate mandatory properties are provided
        missing = set(required) - set(conf.keys())
        if len(missing) > 0:
            self.logger.debug("Missing mandatory parameters: {0}".format(missing))
            return False
        else:
            self.config = conf
            return True
    def parse_rules(self,f=None):
        if self.config['rules_vds']:
            vds = self.config['rules_vds']
            rules = self.query("select * from {0}".format(vds), read=True)
        else:
            rules = pd.read_csv(f)
        return rules
    def connect(self):
        try:
            self.client = flight.FlightClient('grpc+tcp://{0}:32010'.format(self.config['host']))
            self.bearer_token = self.client.authenticate_basic_token(self.config['username'], self.config['password'])
            self.options = flight.FlightCallOptions(headers=[self.bearer_token])
        except Exception as e:
            self.logger.err("Error connecting to server: {0} - {1}".format(self.config['host'], e))
            return False
        else:
            return True
    def disconnect(self):
        self.client.close()
    def query(self, sql, read=False):
        ret = None
        try:
            info = self.client.get_flight_info(flight.FlightDescriptor.for_command(sql + '-- arrow flight'), self.options)
            reader = self.client.do_get(info.endpoints[0].ticket, self.options)
            df = reader.read_pandas()
            if read:
                ret = df
            else:
                ret = True
        except Exception as e:
            self.logger.err("Error submitting query to host: ", e)
            ret = False
            return ret
        else:
            return ret
    def get_views(self):
        df = self.query("select path from sys.views", read=True)
        # extract path
        self.views = df['path'].apply(lambda x: ".".join(['"{0}"'.format(x.strip()) for x in x[1:len(x) - 1].split(",")]).replace("\"", ""))
    def get_privileges(self, groups=False):
        if groups:
            self.privileges = self.query("SELECT grantee_id as grantee, privilege, object_id as object FROM sys.privileges", read=True)
        else:
            self.privileges = self.query("SELECT grantee_id as grantee, privilege, object_id as object FROM sys.privileges where grantee_type='user'", read=True)
    def get_policies(self):
        self.policies = self.query('select name, "sql" as policy from sys.user_defined_functions', read=True)
    def check_permission(self, grantee, privilege, object):
        exists = self.privileges.loc[(self.privileges['grantee'].str.contains(grantee)) & (self.privileges['privilege'].str.contains(privilege, case=False)) & (self.privileges['object'].str.contains(object.replace("\"", ""), case=False))].any().all()
        if exists:
            return True
        else:
            return False
    def check_exists(self, df, string, ret=False):
        obj = string.replace("\"", "")
        tmp = df.loc[df.str.contains(obj, case=False)]
        exists = tmp.any().all()
        if exists and not ret:
            return True
        elif exists and ret:
            return tmp.values[0]
        else:
            return False
    def validate_and_apply_policy(self, name, policy, rule_str):
        if self.policies.loc[(self.policies['name'].str.contains(name, case=False)) & (self.policies['policy'].str.contains(rule_str, case=False))].any().all():
            self.logger.debug("Policy does not need to change")
            return False
        else:
            return self.query(policy)
    def create_dataset_policy(self, dataset):
        # if being run for the first time then get the privileges from Dremio
        if self.policies is None:
            self.get_policies()
        target_ds_name = dataset[self.config['policy_path_identifier']].values[0]+"."+dataset[self.config['dataset_identifier']].values[0]
        ds_name = self.check_exists(self.views, target_ds_name, ret=True)
        if not ds_name:
            self.logger.debug("VDS {0} does not exist".format(target_ds_name))
            return False
        # get unique pairs for building up the case statement
        unique = dataset.groupby(self.config['user_identifier'])
        _filter = dataset[self.config['filter_identifier']].values[0]
        function_name = "{0}_rbac".format(ds_name)
        function_def = "{0}({1} VARCHAR)".format(function_name,_filter)
        access_policy_func = "{0}({1})".format(function_name,_filter)
        res = False
        function_str = """CREATE OR REPLACE FUNCTION {0}
    RETURNS BOOLEAN
        RETURN """.format(function_def)
        rule_str = "SELECT CASE"
        if unique.ngroups == 0:
            return False
        for key, item in unique:
            user = item[self.config['user_identifier']].values[0]
            groups = item[self.config['criteria_identifier']].values
            for group in groups:
                if group is None:
                    continue
                rule_str += "\n\t\t\t\tWHEN query_user()='{0}' and {1}='{2}' THEN true".format(user, _filter, group)
            rule_str += "\n\t\t\t\tWHEN query_user()='{0}' THEN true".format(self.config['username'])
            rule_str += "\n\t\t\t\tELSE false\nEND;"
        # create rule
        res = self.validate_and_apply_policy(function_name, function_str+rule_str, rule_str)
        if res:
            # grant execute permissions for admin
            grant_execute = 'GRANT EXECUTE ON FUNCTION {0} TO user "{1}"'.format(function_name, self.config['username'])
            # create rule
            res = self.query(grant_execute)
            add_policy_to_vds = 'ALTER VIEW {0} ADD ROW ACCESS POLICY {1}'.format(ds_name, access_policy_func)
            res = self.query(add_policy_to_vds)
    def validate_and_apply_privilege(self, user, vds, privilege):
        if self.check_permission(user, privilege, vds) and privilege.lower() != "revoke":
            self.logger.debug("Privilege {0} already exists for user {1} on vds {2}".format(privilege, user, vds))
            return True
        else:
            if privilege.lower() == "select":
                stmnt = 'GRANT {0} ON VDS {1} to USER "{2}";'.format(privilege, vds, user)
            elif privilege.lower() == "revoke":
                stmnt = 'REVOKE ALL ON VDS {1} FROM USER "{2}";'.format(privilege, vds, user)
        res = self.query(stmnt)
        self.logger.debug("Successfully updated privilege {0} for user {1} on vds {2}".format(privilege, user, vds))
        return res
    def build_grants(self, dataset):
        # if being run for the first time then get the privileges from Dremio
        if self.privileges is None:
            self.get_privileges()
        # get unique rows based on Service, VDS and Access
        df = dataset.drop_duplicates(subset=[self.config['user_identifier'], self.config['dataset_identifier'], self.config['privilege_identifier']])
        for idx, r in df.iterrows():
            user = r[self.config['user_identifier']]
            access = r[self.config['privilege_identifier']]
            if r[self.config['path_identifier']] != "-":
                target_vds = '"{0}"."{1}"'.format(r[self.config['path_identifier']], r[self.config['dataset_identifier']].upper())
                ds_name = self.check_exists(self.views, target_vds, ret=True)
                # check if vds exists
                if not ds_name:
                    self.logger.debug("VDS {0} does not exist".format(target_vds))
                    return False
                # check if the permission already exists if not then apply it
                res = self.validate_and_apply_privilege(user=user, vds=ds_name, privilege=access)
            policy_target_vds = '"{0}"."{1}"'.format(r[self.config['policy_path_identifier']], r[self.config['dataset_identifier']])
            ds_name = self.check_exists(self.views, policy_target_vds, ret=True)
            if ds_name:
                res = self.validate_and_apply_privilege(user=user, vds=ds_name, privilege=access)