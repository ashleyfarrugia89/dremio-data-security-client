import configparser
from pyarrow import flight
import pandas as pd

class Helper:
    client = None
    config = None
    options = None
    views = None
    privileges = None
    policies = None
    def parse_config(self, conf_file, required):
        config = configparser.ConfigParser()
        config.read(conf_file)
        conf = config['default']
        # validate mandatory properties are provided
        missing = set(required) - set(conf.keys())
        if len(missing) > 0:
            print("Missing mandatory parameters: {0}".format(missing))
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
            print("Error connecting to server: {0} - {1}".format(self.config['host'], e))
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
            print("Error submitting query to host: ", e)
            ret = False
            return ret
        else:
            return ret
    def get_views(self):
        df = self.query("select path from sys.views", read=True)
        # extract path
        self.views = df['path'].apply(lambda x: ".".join(['"{0}"'.format(x.strip()) for x in x[1:len(x) - 1].split(",")]))
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
    def check_exists(self, df, string, column=False):
        if column:
            exists = df[column].loc[df[column].str.contains(string, case=False)].any().all()
        else:
            exists = df.loc[df.str.contains(string, case=False)].any().all()
        if exists:
            return True
        else:
            return False
    def validate_and_apply_policy(self, name, policy):
        if self.policies.loc[(self.policies['name'].str.contains(name, case=False)) & (self.policies['policy'].str.contains(policy, case=False))].any().all():
            print("Policy does not need to change")
            return False
        else:
            return self.query(policy)
    def create_dataset_policy(self, dataset, skip=False):
        # if being run for the first time then get the privileges from Dremio
        if self.policies is None:
            self.get_policies()
        ds_name = dataset[self.config['dataset_identifier']].values[0]
        # get unique pairs for building up the case statement
        unique = dataset.groupby(self.config['user_identifier'])
        _filter = dataset[self.config['filter_identifier']].values[0]
        parent_path = dataset[self.config['parent_path_identifier']].values[0]+"."+ds_name
        function_name = "{0}_rbac".format(parent_path)
        function_def = "{0}({1} VARCHAR)".format(function_name,_filter)
        access_policy_func = "{0}({1})".format(function_name,_filter)
        res = False
        if not skip:
            rule_str = """CREATE OR REPLACE FUNCTION {0}
        RETURNS BOOLEAN
            RETURN SELECT CASE""".format(function_def)
            if unique.ngroups == 0:
                return False
            if unique.ngroups == 1:
                key = list(unique.groups.keys())[0]
                item = unique.get_group(key)
                user = item[self.config['user_identifier']].values[0]
                criteria = item[self.config['criteria_identifier']].values
                rule_str += "\n\tWHEN query_user()='{0}' and {1}='{2}' THEN true".format(user, _filter, criteria[0])
                rule_str += "\n\tELSE false\nEND;"
            else:
                for key, item in unique:
                    user = item[self.config['user_identifier']].values[0]
                    groups = item[self.config['criteria_identifier']].values
                    for group in groups:
                        if group is None:
                            continue
                        rule_str += "\n\t\t\t\tWHEN query_user()='{0}' and {1}='{2}' THEN true".format(user, _filter, group)
                rule_str += "\n\t\t\t\tELSE false\nEND;"
            # create rule
            res = self.validate_and_apply_policy(function_name, rule_str)
        if res or skip:
            # grant execute permissions for admin
            grant_execute = 'GRANT EXECUTE ON FUNCTION {0} TO user "{1}"'.format(function_name, self.config['username'])
            # create rule
            res = self.query(grant_execute)
            add_policy_to_vds = 'ALTER VIEW {0} ADD ROW ACCESS POLICY {1}'.format(parent_path, access_policy_func)
            res = self.query(add_policy_to_vds)
    def validate_and_apply_privilege(self, user, vds, privilege):
        if self.check_permission(user, privilege, vds) and privilege.lower() != "revoke":
            print("Privilege {0} already exists for user {1} on vds {2}".format(privilege, user, vds))
            return True
        else:
            if privilege.lower() == "select":
                stmnt = 'GRANT {0} ON VDS {1} to USER "{2}";'.format(privilege, vds, user)
            elif privilege.lower() == "revoke":
                stmnt = 'REVOKE ALL ON VDS {1} FROM USER "{2}";'.format(privilege, vds, user)
        res = self.query(stmnt)
        print("Successfully updated privilege {0} for user {1} on vds {2}".format(privilege, user, vds))
        return res
    def build_grants(self, dataset):
        # if being run for the first time then get the privileges from Dremio
        if self.privileges is None:
            self.get_privileges()
        # get unique rows based on Service, VDS and Access
        df = dataset.drop_duplicates(subset=[self.config['user_identifier'], self.config['dataset_identifier'], self.config['privilege_identifier']])
        for idx, r in df.iterrows():
            user = r[self.config['user_identifier']]
            vds = '"{0}"."{1}"'.format(r[self.config['path_identifier']], r[self.config['dataset_identifier']].upper())
            # check if vds exists
            if not self.check_exists(self.views, vds):
                print("VDS {0} does not exist".format(vds))
                return False
            # check if the permission already exists if not then apply it
            access = r[self.config['privilege_identifier']]
            res = self.validate_and_apply_privilege(user=user, vds=vds, privilege=access)
            if res:
                # check parent
                parent = '"{0}"."{1}"'.format(r[self.config['parent_path_identifier']], r[self.config['dataset_identifier']])
                if self.check_exists(self.views, parent):
                    res = self.validate_and_apply_privilege(user=user, vds=parent, privilege=access)