Dremio Data Security Client
====
This unofficial script is to management data security inside your Dremio environment. It enables administrators to configure role-based-access-control to provide least-privileged access to your data. The privileges are based on a configuration entity that will provide understanding of who should have access of which objects and the data within them.

The key features of this tool are:

- **Object Level Permissions**: This will grant or deny access to specific objects within Dremio, initially these objects will be Virtual Data Sets (VDS).
- **Row-level Permissions**: This will create rules within Dremio to enable differential privacy, to provide zero-trust policies within your organisation.