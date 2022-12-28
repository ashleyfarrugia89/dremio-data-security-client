Dremio Data Security Client
====
This unofficial script is to management data security inside your Dremio environment. It enables administrators to configure role-based-access-control to provide least-privileged access to your data. The privileges are based on a configuration entity that will provide understanding of who should have access of which objects and the data within them.

The key features of this tool are:

- **Object Level Permissions**: This will grant or deny access to specific objects within Dremio, initially these objects will be Virtual Data Sets (VDS).
- **Row-level Permissions**: This will create rules within Dremio to enable differential privacy, to provide zero-trust policies within your organisation.

## Pre-requisite
This script has a number of dependencies that need to be satisfied before we can execute it. These dependencies are listed below.

### Configuration File: 
The following table provides understanding the configuration parameters that are provided for the script to execute successfully and impose the restrictions that you want within your data ecosystem.

| Variable  	| Description  | Required 	|
|---	|:---	|	---|
| host 	| Dremio host either DNS or IP Address 	| Yes 	|
| username 	| Dremio administrator username 	| Yes 	|
| password 	| Dremio administrator password 	| Yes 	|
| grained 	| Determines if you want to create fine-grained rules to manage access to your data on a row-level 	| Yes 	|
| rules_vds 	| This is the rules entity that will be used by the script to create the rules within Dremio, these are be provided using a CSV or VDS inside Dremio 	| Either rules_vds and rules_csv are required	|
| rules_csv 	| This is the rules entity that will be used by the script to create the rules within Dremio, these are be provided using a CSV or VDS inside Dremio 	| Either rules_vds and rules_csv are required 	|
| dataset_identifier 	|  Identifier for finding the VDS that you want to create the rule for within your rules entity	| Yes 	|
| user_identifier 	| Identifier for finding the VDS that you want to create the rule for within your rules entity 	| Yes 	|
| path_identifier 	| Identifier for finding the path of the VDS that you want to create the rule for within your rules entity 	| Yes 	|
| policy_path_identifier 	| Identifier for finding the parent path of the VDS that you want to create the rule for within your rules entity 	| Yes 	|
| privilege_identifier 	| Identifier for the privilege that we want to apply to the VDS | Yes 	|
| filter_identifier 	| Identifier for the filter that we are using to impose the row-level data access 	|   Yes for row-level control |
| criteria_identifier 	| Identifier for the criteria that we will use within the policy to determine the rows to return for the row-level data access|   Yes for row-level control |

### Rules Entity
The rules entity is used to determine who should have access to which objects and what access they should have. This can be provided via a .csv file or it can use an external source through a Dremio VDS. This means that your rules can be derived from a centrally managed source e.g., Postgres., to ensure consistent access control is enabled throughout the organisation. The following Table gives an example of what this rules entity should look like for the nyc_trips dataset.

| User  	| Dataset  | Criteria 	| Access 	| Path 	| Filter 	| PolicyPath 	|
|---	|:---	|:--- |:--- |:--- |:---|	---|
| ashley.farrugia@dremio.com  	| nyc_trips  | CMT 	|  SELECT 	|  CoreDataAccessLayer 	| vendor_id 	| BusinessDataAccessLayer 	|
| ashley.farrugia@dremio.com  	| nyc_trips  | DDS 	|  SELECT 	|  CoreDataAccessLayer 	| vendor_id 	| BusinessDataAccessLayer 	|

,where <i>User</i> is the username that we want to change the privilege for, <i>Dataset</i> is the VDS the permissions will be applied to, <i>Criteria</i> is the filter criteria for providing row-level control, <i>Access</i> the permission applied to the Dataset, <i>Path</i> is the absolute path inside Dremio</i>, <i>Filter</i> is the column that we will filter by; for row-level fine-grained control, and <i>PolicyPath</i> the absolute path for the VDS that the row-level access permissions are applied to.


If you have any questions or issues then please contact me [ashley.farrugia@dremio.com](mailto:ashley.farrugia@dremio.com).