# Never execute analyzed repository content

Repository archives, manifests, lockfiles, configuration, and source files are untrusted data: the system may parse and inspect them but will not install dependencies, run builds or hooks, import modules, or execute repository code. This deliberately limits dynamic reachability claims, but establishes a clear isolation boundary for local and hosted analysis and keeps malicious repositories from turning investigation into remote code execution.
