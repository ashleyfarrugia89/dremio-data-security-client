from helper import Helper

if __name__ == "__main__":
    h = Helper()
    # require properties
    req_properties = ["host", "username", "password", "dataset_identifier", "user_identifier", "path_identifier", "policy_path_identifier",
                      "privilege_identifier", "filter_identifier", "criteria_identifier"]
    if h.parse_config('dremio-rbac.conf', req_properties):
        # connect to the server
        h.connect()
        # get the list of views that are available from Dremio
        h.get_views()
        # get access control rules from vds
        rules = h.parse_rules()
        datasets = rules.groupby('DT')
        for key, dataset in datasets:
             if h.config['fine-grained'] == "True":
                 h.create_dataset_policy(dataset, skip=False)
             else:
                 h.build_grants(dataset)
        h.disconnect()

