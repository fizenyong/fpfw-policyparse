import xml.etree.ElementTree as ET
import csv

# This script parses an XML file containing firewall configurations and outputs the parsed data in a structured format.

infile = "exported_data.xml"

print("Parsing XML file...")
tree = ET.parse(infile)
root = tree.getroot()

# Parsing hosts
print("Parsing host configurations...")
host_roots = []
for child in root:
    if child.tag == "host":
        host_roots.append(child)

host_policy = []

for hosts in host_roots:
    name = hosts.attrib["name"]
    comment = hosts.attrib["comment"] if "comment" in hosts.attrib else ""
    ipaddr = hosts.find("mvia_address").attrib["address"]

    host_policy.append(
        {
            "name": name,
            "description": comment,
            "ip": ipaddr,
        }
    )

# Parsing IP Range
print("Parsing iprange configurations...")
network_roots = [child for child in root if child.tag == "network"]
network_policy = []

for hosts in network_roots:
    name = hosts.attrib["name"]
    comment = hosts.attrib["comment"] if "comment" in hosts.attrib else ""
    ipaddr = hosts.attrib["ipv4_network"]

    network_policy.append(
        {
            "name": name,
            "description": comment,
            "ip/mask": ipaddr,
        }
    )

# Parsing sub-policies
print("Parsing sub-policy configurations...")
fw_sub_policy_roots = [child for child in root if child.tag == "fw_sub_policy"]
sub_policy = []

for rules in fw_sub_policy_roots:
    key = rules[0][0].attrib["tag"]
    disable = rules[0][0].attrib["is_disabled"]
    comment = rules[0][0].attrib["comment"] if "comment" in rules[0][0].attrib else ""
    source = [src.attrib["value"] for src in rules[0][0][0][0][0]]
    destination = [dst.attrib["value"] for dst in rules[0][0][0][0][1]]
    service = [svc.attrib["value"] for svc in rules[0][0][0][0][2]]
    action = rules[0][0][0][1].attrib["type"]

    sub_policy.append(
        {
            "tag": key,
            "is_disabled": disable,
            "comment": comment,
            "source": source,
            "destination": destination,
            "service": service,
            "action": action,
        }
    )

# Parsing access policies
print("Parsing access policy configurations...")
fw_policy_roots = root.find(".//fw_policy")
access_entry_children = []

for access_entry in fw_policy_roots.findall(".//access_entry"):
    for child in access_entry:
        access_entry_children.append(child)

access_policy = []

for rules in access_entry_children:
    key = rules.attrib["tag"]
    disable = rules.attrib["is_disabled"]
    comment = rules.attrib["comment"] if "comment" in rules.attrib else ""
    source = [src.attrib["value"] for src in rules[0][0][0]]
    destination = [dst.attrib["value"] for dst in rules[0][0][1]]
    service = [svc.attrib["value"] for svc in rules[0][0][2]]
    action = rules[0][1].attrib["type"]

    access_policy.append(
        {
            "tag": key,
            "is_disabled": disable,
            "comment": comment,
            "source": source,
            "destination": destination,
            "service": service,
            "action": action,
        }
    )

# Output results
print("Outputting host configurations...")
with open("hosts.csv", mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)

    writer.writerow(host_policy[0].keys())
    for emp in host_policy:
        writer.writerow(emp.values())

print("Outputting iprange configurations...")
with open("iprange.csv", mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)

    writer.writerow(network_policy[0].keys())
    for emp in network_policy:
        writer.writerow(emp.values())


def write_policy_to_csv(filename, policy):
    """Writes policy configurations to a CSV file."""
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if policy:
            headers = [
                "rule_name",
                "description",
                "source_addresses",
                "destination_addresses",
                "services",
                "disabled",
                "action",
            ]
            writer.writerow(headers)

            for emp in policy:
                writer.writerow(
                    [
                        emp["tag"],
                        emp["comment"] if emp["comment"] else "",
                        "; ".join(emp["source"]),
                        "; ".join(emp["destination"]),
                        "; ".join(emp["service"]),
                        "disable" if emp["is_disabled"] == "true" else "",
                        emp["action"],
                    ]
                )

        else:
            print(f"No data found for {filename}.")


print("Outputting policy configurations...")
# Write sub-policy configurations
write_policy_to_csv("subpolicy.csv", sub_policy)

# Write access policy configurations
write_policy_to_csv("policy.csv", access_policy)

print("\nParsing completed.")