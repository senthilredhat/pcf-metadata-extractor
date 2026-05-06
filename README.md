# Cloud Foundry Application Metadata Extractor (v3 API)

`extract-pcf-inventory.sh` collects comprehensive Cloud Foundry org, space, app, and process metadata using the **v3 API**.
It produces detailed CSV reports for auditing, reporting, and migration analysis (e.g., CF → OpenShift).

## Features

- **v3 API Support:** Works on foundations with v2 API disabled
- **Comprehensive Metadata:** Org, space, app, processes, buildpacks, routes, domains, services, security groups
- **Actual Resource Usage:** Extracts real-time memory and disk usage from running instances (for OpenShift sizing)
- **Volume Service Detection:** Identifies persistent storage requirements for PersistentVolumeClaim (PVC) planning
- **Docker Support:** Extracts Docker image and registry information for containerized apps
- **Security:** Sanitizes sensitive environment variables (passwords, tokens, secrets, keys)
- **Robust Error Handling:** Retry logic with exponential backoff for transient failures
- **Pagination:** Automatically handles large datasets (>50 items per page)
- **Security Groups:** Captures org-level, space-level, and global security group assignments
- **RFC 4180 CSV:** Proper CSV escaping for special characters (commas, quotes, newlines)
- **Data Quality Tracking:** Reports warnings for incomplete data
- **Debug Mode:** Optional `--debug` flag for verbose diagnostic output

## Requirements

- Logged into Cloud Foundry (`cf login`)
- `cf` CLI and `jq` installed

## Usage

```bash
chmod +x extract-pcf-inventory.sh
./extract-pcf-inventory.sh <org_name> [options]
./extract-pcf-inventory.sh -h|--help
```

### Options

- `-o, --output FILE` - Custom output CSV file path (default: `pcfusage_<org>_YYYYMMDDHHMMSS.csv`)
- `-d, --debug` - Enable verbose diagnostic output
- `--no-env-vars` - Skip extracting environment variables (Env Vars column will be empty)
- `-h, --help` - Display comprehensive help message

### Examples

```bash
# Basic extraction
./extract-pcf-inventory.sh abc-company

# Custom output file
./extract-pcf-inventory.sh abc-company -o /tmp/my-report.csv

# Enable debug output
./extract-pcf-inventory.sh abc-company --debug

# Show help
./extract-pcf-inventory.sh --help
```

## Output

Generates a timestamped CSV file such as:
```
pcfusage_abc-company_20260316143022.csv
```

### CSV Columns

The report includes the following 22 columns:

| Column                   | Description                                       | OpenShift Migration Use |
|--------------------------|---------------------------------------------------|------------------------|
| **Org**                  | Organization name                                 | - |
| **Space**                | Space name                                        | Namespace planning |
| **App**                  | Application name                                  | Deployment name |
| **Process Type**         | Process type (web, worker, etc.)                  | Container type |
| **Instances**            | Number of instances                               | Replica count |
| **Memory(MB)**           | Memory allocation quota in MB                     | Memory limit reference |
| **Disk(MB)**             | Disk allocation quota in MB                       | Ephemeral storage limit reference |
| **Memory Usage(MB)**     | **Actual memory usage** from running instances    | **Memory request/limit sizing** |
| **Disk Usage(MB)**       | **Actual disk usage per instance** from running instances | **Per-pod ephemeral-storage limit** |
| **Total Disk Usage(MB)** | **Total disk usage** (Disk Usage × Instances)     | **⭐ Cluster-wide ephemeral storage capacity** |
| **State**                | Application state (STARTED, STOPPED)              | - |
| **Buildpacks**           | Buildpack names or Docker image                   | S2I/Image selection |
| **Buildpack Details**    | Buildpack versions or Docker registry             | Build configuration |
| **Runtime Version**      | Runtime version (Java, Node.js, etc.)             | Base image selection |
| **Routes**               | Application routes (URLs)                         | Route/Ingress planning |
| **Domains**              | Associated domains                                | Domain configuration |
| **Service Instances**    | Bound service instances with plan details         | Operator/service planning |
| **Service Bindings**     | Service binding names                             | Secret/ConfigMap planning |
| **Volume Services**      | **Persistent volume service names**               | **PVC identification** |
| **Volume Size(GB)**      | **Persistent volume sizes in GB**                 | **PVC capacity planning** |
| **Env Vars**             | Environment variables (sensitive values redacted) | ConfigMap/Secret content |
| **Security Groups**      | Space, org, and global security groups            | NetworkPolicy planning |

### Sample Output

```csv
Org,Space,App,Process Type,Instances,Memory(MB),Disk(MB),Memory Usage(MB),Disk Usage(MB),Total Disk Usage(MB),State,Buildpacks,Buildpack Details,Runtime Version,Routes,Domains,Service Instances,Service Bindings,Volume Services,Volume Size(GB),Env Vars,Security Groups
abc-company,production,api-service,web,3,1024,2048,768,1024,3072,STARTED,java_buildpack,java_buildpack 4.45,11,api.example.com,example.com,mysql [cleardb/spark (managed)],mysql-binding,,,DATABASE_URL=<REDACTED>,space:app-sg;global-running:public_networks
abc-company,production,file-processor,web,2,2048,4096,1536,2800,5600,STARTED,java_buildpack,java_buildpack 4.45,11,files.example.com,example.com,mysql [cleardb/spark (managed)];nfs-volume [nfs/standard (user-provided)],mysql-binding,nfs-volume,50,DATABASE_URL=<REDACTED>;NFS_MOUNT=/data,space:app-sg;global-running:public_networks
abc-company,production,nginx,web,1,512,512,256,128,128,STARTED,nginx:1.21.0,registry:docker.io,,nginx.example.com,example.com,,,,,NGINX_WORKER_PROCESSES=4,global-running:public_networks
```

## Common Uses

### OpenShift Migration Planning

This tool is **optimized for PCF to OpenShift migrations** with critical data for capacity planning:

- **Ephemeral Storage Sizing:**
  - ⚠️ **CRITICAL:** Use `Total Disk Usage(MB)` column for capacity planning, NOT `Disk Usage(MB)`
  - `Disk Usage(MB)` = **per-instance** usage (use for per-pod limits)
  - `Total Disk Usage(MB)` = **total across all instances** (use for cluster capacity)
  - Formula for cluster capacity: `SUM(Total Disk Usage(MB)) × 1.5` (with 50% buffer)
  - Formula for per-pod limit: `Disk Usage(MB) × 1.5`
  
- **Persistent Storage (PVC) Planning:**
  - `Volume Services` identifies apps requiring PersistentVolumeClaims
  - `Volume Size(GB)` provides exact capacity requirements
  - Direct 1:1 mapping from CF volume services to OpenShift PVCs

- **Memory/CPU Right-Sizing:**
  - `Memory Usage(MB)` shows **actual consumption** vs `Memory(MB)` quota
  - Identify over-provisioned apps where quota >> actual usage
  - Set OpenShift requests based on actual usage, limits based on quota

- **Example Migration Calculation:**
  ```
  App A: Instances=3, Disk Usage(MB)=1024, Total Disk Usage(MB)=3072
  → Per-pod limit: 1024MB × 1.5 = 1536Mi
  → Total capacity needed: 3072MB
  
  App B: Instances=2, Disk Usage(MB)=2800, Total Disk Usage(MB)=5600
  → Per-pod limit: 2800MB × 1.5 = 4200Mi
  → Total capacity needed: 5600MB
  
  Cluster ephemeral storage capacity: (3072 + 5600) × 1.5 = 13,008MB ≈ 13Gi
  
  Volume Services: nfs-volume, Volume Size(GB)=50
  → OpenShift: PVC with 50Gi capacity
  ```

### Other Uses

- **Resource Auditing:** Memory, disk, and instance usage across org
- **Buildpack Analysis:** Identify buildpack versions and upgrade candidates
- **Security Review:** Audit security group assignments and environment variable usage
- **Service Mapping:** Document service dependencies and bindings
- **Docker Adoption:** Identify containerized vs buildpack-based applications
- **Compliance Reporting:** Extract configuration data for compliance reviews

## Python implementation (`pcf-inventory-extractor`)

The same CF v3 logic is available as a **Python** package (HTTP via **httpx**, no `jq` at runtime). The original **bash** script `extract-pcf-inventory.sh` remains in the repo as a **reference** implementation.

### Requirements

- Python 3.12+ (see `.python-version`; use **uv** to install the pinned interpreter)
- **CLI:** Cloud Foundry CLI (`cf`) installed and logged in (`cf login`); `pcf-inventory-extract` uses `cf api` and `cf oauth-token` for the API base URL and bearer token.
- **Web UI:** No `cf` session required. You enter the CF API URL (same as `cf login -a`), username, and password; the server performs a UAA password grant and calls the v3 API with the returned bearer token. Use TLS in front of the app for production. SSO-only foundations may disable password grants.
- **TLS:** Outbound HTTPS to Cloud Controller and UAA does **not** verify server certificates by default (`CONFIG_HTTPS_VERIFY` in [`src/pcf_inventory_extractor/constants.py`](src/pcf_inventory_extractor/constants.py)). Set it to `True` to enforce standard certificate validation (recommended for internet-facing endpoints).

### Install (uv)

```bash
uv sync
# optional dev tools (ruff, pytest)
uv sync --all-groups
```

### CLI (same flags as the shell script)

```bash
uv run pcf-inventory-extract <org_name> [-o output.csv] [-d]
```

### Web UI

```bash
uv run pcf-inventory-serve --host 127.0.0.1 --port 8080
```

Add **`--open`** to launch the app in your **default browser** shortly after the server starts (handy on a desktop; in headless or remote-SSH setups it may do nothing or open on the remote display). If you bind with **`--host 0.0.0.0`** or **`::`**, the opened URL is **`http://127.0.0.1:<port>/`**, because those addresses mean “listen on all interfaces,” not a URL the browser can open.

```bash
uv run pcf-inventory-serve --host 127.0.0.1 --port 8080 --open
```

Open the URL (or use **`--open`**), enter the CF API URL, username, password, org name, optional output path, optional debug, and submit to **download** the CSV. After a successful download, the page shows the saved filename and notes that it is in your browser's default Downloads folder (or wherever the browser is configured to save files).

### Develop

```bash
uv run ruff check src tests
uv run pytest
```
