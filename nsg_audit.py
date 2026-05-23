import csv
import json
import subprocess

RISKY_PORTS = {
    "3389": "RDP",
    "22": "SSH",
}

PUBLIC_SOURCES = {"*", "0.0.0.0/0", "Internet", "Any"}


def run_azure_cli(command):
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("Failed to run Azure CLI command:")
        print(" ".join(command))
        print(result.stderr)
        raise SystemExit(1)

    return json.loads(result.stdout)


def list_nsgs(resource_group):
    command = [
        "az.cmd",
        "network",
        "nsg",
        "list",
        "--resource-group",
        resource_group,
        "-o",
        "json",
    ]
    return run_azure_cli(command)


def list_nsg_rules(resource_group, nsg_name):
    command = [
        "az.cmd",
        "network",
        "nsg",
        "rule",
        "list",
        "--resource-group",
        resource_group,
        "--nsg-name",
        nsg_name,
        "-o",
        "json",
    ]
    return run_azure_cli(command)


def normalize(value):
    if value is None:
        return ""
    return str(value).strip()


def get_source(rule):
    source = normalize(rule.get("sourceAddressPrefix"))
    prefixes = rule.get("sourceAddressPrefixes") or []

    if source:
        return source

    if prefixes:
        return ",".join(prefixes)

    return ""


def get_destination_port(rule):
    port = normalize(rule.get("destinationPortRange"))
    ports = rule.get("destinationPortRanges") or []

    if port:
        return port

    if ports:
        return ",".join(ports)

    return ""


def is_public_source(source):
    if source in PUBLIC_SOURCES:
        return True

    sources = [item.strip() for item in source.split(",")]
    return any(item in PUBLIC_SOURCES for item in sources)


def classify_rule(nsg_name, rule):
    access = normalize(rule.get("access"))
    direction = normalize(rule.get("direction"))
    protocol = normalize(rule.get("protocol"))
    source = get_source(rule)
    destination_port = get_destination_port(rule)
    rule_name = normalize(rule.get("name"))
    priority = rule.get("priority")

    findings = []

    if access == "Allow" and direction == "Inbound":
        if destination_port in RISKY_PORTS and is_public_source(source):
            findings.append({
                "nsg_name": nsg_name,
                "rule_name": rule_name,
                "priority": priority,
                "risk_level": "High",
                "issue": f"Public {RISKY_PORTS[destination_port]} exposure",
                "source": source,
                "destination_port": destination_port,
                "protocol": protocol,
                "recommendation": "Restrict source to a trusted IP range, VPN, Bastion, or remove public management access.",
            })

        elif is_public_source(source) and destination_port == "*":
            findings.append({
                "nsg_name": nsg_name,
                "rule_name": rule_name,
                "priority": priority,
                "risk_level": "High",
                "issue": "Inbound allow from public source to all ports",
                "source": source,
                "destination_port": destination_port,
                "protocol": protocol,
                "recommendation": "Avoid broad inbound access. Define specific source ranges and destination ports.",
            })

        elif is_public_source(source):
            findings.append({
                "nsg_name": nsg_name,
                "rule_name": rule_name,
                "priority": priority,
                "risk_level": "Review",
                "issue": "Inbound allow from public source",
                "source": source,
                "destination_port": destination_port,
                "protocol": protocol,
                "recommendation": "Validate business justification and restrict source where possible.",
            })

    return findings


def main():
    resource_group = input("Enter Azure resource group name: ").strip()

    if not resource_group:
        print("Resource group name is required.")
        raise SystemExit(1)

    nsgs = list_nsgs(resource_group)
    all_findings = []

    print("\nAzure NSG Security Audit")
    print("=" * 50)

    for nsg in nsgs:
        nsg_name = nsg.get("name")
        rules = list_nsg_rules(resource_group, nsg_name)

        for rule in rules:
            findings = classify_rule(nsg_name, rule)
            all_findings.extend(findings)

    if not all_findings:
        print("No risky custom NSG rules found.")
    else:
        for finding in all_findings:
            print(f"NSG:            {finding['nsg_name']}")
            print(f"Rule:           {finding['rule_name']}")
            print(f"Priority:       {finding['priority']}")
            print(f"Risk:           {finding['risk_level']}")
            print(f"Issue:          {finding['issue']}")
            print(f"Source:         {finding['source']}")
            print(f"Port:           {finding['destination_port']}")
            print(f"Protocol:       {finding['protocol']}")
            print(f"Recommendation: {finding['recommendation']}")
            print("-" * 50)

    with open("nsg_findings.csv", "w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "nsg_name",
            "rule_name",
            "priority",
            "risk_level",
            "issue",
            "source",
            "destination_port",
            "protocol",
            "recommendation",
        ]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_findings)

    print("\nReport written to nsg_findings.csv")


if __name__ == "__main__":
    main()
