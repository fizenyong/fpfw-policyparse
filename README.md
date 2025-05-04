# Forcepoint Firewall XML Parser

Python script to parse an exported Forcepoint firewall engine policy (`exported_data.xml` from Management Client) and extract the XML firewall policy into a structured CSV format. The output CSV file contains key details for migrating firewall rules to other firewall solutions, which are typically configured via CLI.

## Features

* **Input: Forcepoint Firewall Policy**
  * Extracts the firewall policy details from exported XML file (`exported_data.xml`)

* **Output: Structured CSV Files**
  * **hosts.csv**:
    * Contains a list of host elements, which represent individual IP addresses of devices within the firewall policy.
    * Columns include: *Host Name*, *Description*, *IP Address*

  * **iprange.csv**:
    * Contains a list of Address Range elements, which can specify any continuous range of IP addresses.
    * Columns include: *Range Name*, *Description*, *IP Address/Mask*

  * **subpolicy.csv**:
    * Contains a list of Sub-Policy elements.
    * Columns include: *Rule Name*, *Description*, *Source*, *Destination*, *Service*, *IsDisabled*, *Action*

  * **policy.csv**:
    * Contains a list of Policy elements.
    * Columns include: *Rule Name*, *Description*, *Source*, *Destination*, *Service*, *IsDisabled*, *Action*

## Getting Started

* Python 3.12 or higher
* Required Python packages (Both are included in the Python Standard Library):
  * xml.etree.ElementTree
  * csv

## Installation

1. Clone the repository
2. No external dependencies are required for this script, as it uses Python's built-in libraries.

## How to Use

1. Place the Forcepoint firewall's exported XML configuration file `exported_data.xml` on the same directory.

2. Run the script to parse the XML file.

   ```bash
   python parse_allpolicy.py
   ```

3. The script will process the `exported_data.xml` file and create output CSV files named `hosts.csv`, `iprange.csv`, `subpolicy.csv` and `policy.csv`  on the same directory.

## Example

The output CSV file (`policy.csv`) will look like:

```csv
Rule Name, Description, Source, Destination, Service, Disabled, Action
rule1, Blacklist, ANY, IPRange1, ANY, disable, discard
rule2, Allow HTTP, ANY, ANY, HTTP, , allow
```
