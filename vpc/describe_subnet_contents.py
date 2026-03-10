#!/usr/bin/env python3
"""
AWS Subnet IP Analyzer
Breaks down which IP addresses in a subnet are in use and what AWS resource is at each IP.

Usage:
    python describe_subnet_contents.py --profile <aws_profile> --subnet-id <subnet-id>
    python describe_subnet_contents.py --profile <aws_profile> --subnet-id <subnet-id> --output json
    python describe_subnet_contents.py --profile <aws_profile> --subnet-id <subnet-id> --show-free
"""

import argparse
import ipaddress
import json
import sys
import boto3
from botocore.exceptions import ProfileNotFound, ClientError, NoCredentialsError
from collections import defaultdict


def get_boto3_session(profile: str) -> boto3.Session:
    """Create a boto3 session using the given AWS profile."""
    try:
        session = boto3.Session(profile_name=profile)
        # Validate credentials exist
        session.client("sts").get_caller_identity()
        return session
    except ProfileNotFound:
        print(f"[ERROR] AWS profile '{profile}' not found.")
        print("Available profiles:", boto3.Session().available_profiles)
        sys.exit(1)
    except NoCredentialsError:
        print(f"[ERROR] No credentials found for profile '{profile}'.")
        sys.exit(1)
    except ClientError as e:
        print(f"[ERROR] Could not authenticate with profile '{profile}': {e}")
        sys.exit(1)


def get_subnet(session: boto3.Session, subnet_id: str) -> dict:
    """Fetch subnet details."""
    ec2 = session.client("ec2")
    try:
        response = ec2.describe_subnets(SubnetIds=[subnet_id])
        subnets = response.get("Subnets", [])
        if not subnets:
            print(f"[ERROR] Subnet '{subnet_id}' not found.")
            sys.exit(1)
        return subnets[0]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidSubnetID.NotFound":
            print(f"[ERROR] Subnet '{subnet_id}' does not exist.")
        else:
            print(f"[ERROR] Failed to describe subnet: {e}")
        sys.exit(1)


def get_subnet_name(subnet: dict) -> str:
    """Extract Name tag from subnet."""
    for tag in subnet.get("Tags", []):
        if tag["Key"] == "Name":
            return tag["Value"]
    return "(no name)"


def collect_eni_ips(session: boto3.Session, subnet_id: str) -> dict:
    """
    Collect all IPs assigned via Elastic Network Interfaces in the subnet.
    Returns: { ip_str: { "resource_type": ..., "resource_id": ..., "description": ... } }
    """
    ec2 = session.client("ec2")
    ip_map = {}

    paginator = ec2.get_paginator("describe_network_interfaces")
    pages = paginator.paginate(Filters=[{"Name": "subnet-id", "Values": [subnet_id]}])

    for page in pages:
        for eni in page["NetworkInterfaces"]:
            eni_id = eni["NetworkInterfaceId"]
            description = eni.get("Description", "")
            attachment = eni.get("Attachment", {})
            interface_type = eni.get("InterfaceType", "interface")

            # Determine resource type and ID from the ENI
            resource_type, resource_id = resolve_eni_resource(eni)

            # Primary private IP
            private_ip = eni.get("PrivateIpAddress")
            if private_ip:
                ip_map[private_ip] = {
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "eni_id": eni_id,
                    "description": description,
                    "interface_type": interface_type,
                    "status": eni.get("Status", "unknown"),
                    "public_ip": eni.get("Association", {}).get("PublicIp"),
                    "is_primary": True,
                }

            # Secondary private IPs
            for addr in eni.get("PrivateIpAddresses", []):
                ip = addr.get("PrivateIpAddress")
                is_primary = addr.get("Primary", False)
                if ip and ip != private_ip:
                    ip_map[ip] = {
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "eni_id": eni_id,
                        "description": description,
                        "interface_type": interface_type,
                        "status": eni.get("Status", "unknown"),
                        "public_ip": addr.get("Association", {}).get("PublicIp"),
                        "is_primary": False,
                    }

            # IPv4 prefixes (for EKS/containers)
            for prefix in eni.get("Ipv4Prefixes", []):
                cidr = prefix.get("Ipv4Prefix")
                if cidr:
                    ip_map[f"PREFIX:{cidr}"] = {
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "eni_id": eni_id,
                        "description": f"IPv4 prefix delegation - {description}",
                        "interface_type": interface_type,
                        "status": eni.get("Status", "unknown"),
                        "public_ip": None,
                        "is_primary": False,
                    }

    return ip_map


def resolve_eni_resource(eni: dict) -> tuple:
    """
    Determine the AWS resource type and ID attached to an ENI.
    Returns (resource_type, resource_id).
    """
    description = eni.get("Description", "")
    interface_type = eni.get("InterfaceType", "interface")
    attachment = eni.get("Attachment", {})
    requester_id = eni.get("RequesterId", "")
    requester_managed = eni.get("RequesterManaged", False)

    # EC2 instance
    instance_id = attachment.get("InstanceId")
    if instance_id:
        return ("EC2 Instance", instance_id)

    # ELB / ALB / NLB
    if description.startswith("ELB ") or interface_type == "network_load_balancer":
        return ("Load Balancer", description)

    if interface_type == "gateway_load_balancer":
        return ("Gateway Load Balancer", description)

    if interface_type == "gateway_load_balancer_endpoint":
        return ("Gateway Load Balancer Endpoint", eni["NetworkInterfaceId"])

    # NAT Gateway
    if description.startswith("Interface for NAT Gateway") or interface_type == "nat_gateway":
        nat_id = description.replace("Interface for NAT Gateway ", "").strip()
        return ("NAT Gateway", nat_id or eni["NetworkInterfaceId"])

    # VPC Endpoint
    if interface_type == "vpc_endpoint":
        return ("VPC Endpoint", description or eni["NetworkInterfaceId"])

    # Lambda
    if description.startswith("AWS Lambda VPC ENI") or interface_type == "lambda":
        return ("Lambda Function", description)

    # EKS / Fargate
    if "aws-K8S" in description or "eks" in description.lower():
        return ("EKS / Kubernetes", description)

    if "fargate" in description.lower():
        return ("Fargate Task", description)

    # ECS
    if "ecs" in description.lower():
        return ("ECS Task/Service", description)

    # RDS
    if "rdsnetwork" in description.lower() or interface_type == "branch":
        return ("RDS / Aurora", description)

    # ElastiCache
    if "elasticache" in description.lower():
        return ("ElastiCache", description)

    # Directory Service
    if "aws-managed-ad" in description.lower() or "directory" in description.lower():
        return ("Directory Service", description)

    # Transit Gateway / VPN
    if interface_type in ("transit_gateway", "vpn"):
        return (interface_type.replace("_", " ").title(), description or eni["NetworkInterfaceId"])

    # Requester-managed (service-linked)
    if requester_managed:
        return (f"AWS Managed ({requester_id})", description or eni["NetworkInterfaceId"])

    # Unattached ENI
    if not attachment:
        return ("Unattached ENI", eni["NetworkInterfaceId"])

    # Generic fallback
    return ("ENI / Unknown Service", description or eni["NetworkInterfaceId"])


def get_aws_reserved_ips(network: ipaddress.IPv4Network) -> dict:
    """
    Return the 5 AWS-reserved IPs for a subnet with explanations.
    See: https://docs.aws.amazon.com/vpc/latest/userguide/subnet-sizing.html
    """
    hosts = list(network.hosts())
    reserved = {
        str(network.network_address): "AWS Reserved – Network address",
        str(hosts[0]): "AWS Reserved – VPC router",
        str(hosts[1]): "AWS Reserved – DNS server",
        str(hosts[2]): "AWS Reserved – Future use",
        str(network.broadcast_address): "AWS Reserved – Broadcast address",
    }
    return reserved


def format_table(subnet: dict, network: ipaddress.IPv4Network, ip_map: dict,
                 reserved: dict, show_free: bool) -> str:
    """Format results as a human-readable table."""
    lines = []
    subnet_name = get_subnet_name(subnet)

    lines.append("=" * 80)
    lines.append(f"  AWS Subnet IP Analyzer")
    lines.append("=" * 80)
    lines.append(f"  Subnet ID   : {subnet['SubnetId']}")
    lines.append(f"  Name        : {subnet_name}")
    lines.append(f"  CIDR Block  : {subnet['CidrBlock']}")
    lines.append(f"  AZ          : {subnet['AvailabilityZone']}")
    lines.append(f"  VPC ID      : {subnet['VpcId']}")
    lines.append(f"  Total IPs   : {network.num_addresses}")
    lines.append(f"  Usable IPs  : {network.num_addresses - 5} (minus 5 AWS reserved)")
    lines.append(f"  In Use      : {len(ip_map)}")
    lines.append(f"  Free        : {network.num_addresses - 5 - len(ip_map)}")
    lines.append("=" * 80)

    # Header
    lines.append(f"\n{'IP Address':<18} {'Status':<12} {'Resource Type':<30} {'Resource ID / Description'}")
    lines.append("-" * 100)

    # Print prefix delegations separately
    prefixes = {k: v for k, v in ip_map.items() if k.startswith("PREFIX:")}
    regular_ips = {k: v for k, v in ip_map.items() if not k.startswith("PREFIX:")}

    # Iterate all IPs in subnet order
    for ip_obj in network:
        ip_str = str(ip_obj)

        if ip_str in reserved:
            label = reserved[ip_str]
            lines.append(f"{ip_str:<18} {'RESERVED':<12} {label:<30}")
            continue

        if ip_str in regular_ips:
            info = regular_ips[ip_str]
            status = "IN USE"
            rtype = info["resource_type"]
            rid = info["resource_id"]
            public = f"  [public: {info['public_ip']}]" if info.get("public_ip") else ""
            secondary = " (secondary)" if not info["is_primary"] else ""
            lines.append(f"{ip_str:<18} {status:<12} {rtype:<30} {rid}{public}{secondary}")
        else:
            if show_free:
                lines.append(f"{ip_str:<18} {'FREE':<12}")

    # Prefix delegations
    if prefixes:
        lines.append("\n--- IPv4 Prefix Delegations ---")
        for key, info in prefixes.items():
            cidr = key.replace("PREFIX:", "")
            lines.append(f"  {cidr:<20} {info['resource_type']:<30} {info['resource_id']}")
            lines.append(f"  {'':20} ENI: {info['eni_id']}  Desc: {info['description']}")

    lines.append("\n" + "=" * 80)
    return "\n".join(lines)


def format_json(subnet: dict, network: ipaddress.IPv4Network, ip_map: dict,
                reserved: dict) -> str:
    """Format results as JSON."""
    subnet_name = get_subnet_name(subnet)
    usable = network.num_addresses - 5
    free = usable - len({k: v for k, v in ip_map.items() if not k.startswith("PREFIX:")})

    entries = []

    for ip_obj in network:
        ip_str = str(ip_obj)
        if ip_str in reserved:
            entries.append({"ip": ip_str, "status": "reserved", "description": reserved[ip_str]})
        elif ip_str in ip_map:
            info = ip_map[ip_str]
            entries.append({
                "ip": ip_str,
                "status": "in_use",
                "resource_type": info["resource_type"],
                "resource_id": info["resource_id"],
                "eni_id": info["eni_id"],
                "eni_description": info["description"],
                "interface_type": info["interface_type"],
                "eni_status": info["status"],
                "public_ip": info.get("public_ip"),
                "is_primary_ip": info["is_primary"],
            })
        else:
            entries.append({"ip": ip_str, "status": "free"})

    # Add prefix delegations
    for key, info in ip_map.items():
        if key.startswith("PREFIX:"):
            entries.append({
                "ip": key.replace("PREFIX:", ""),
                "status": "prefix_delegation",
                "resource_type": info["resource_type"],
                "resource_id": info["resource_id"],
                "eni_id": info["eni_id"],
                "eni_description": info["description"],
            })

    output = {
        "subnet": {
            "subnet_id": subnet["SubnetId"],
            "name": subnet_name,
            "cidr_block": subnet["CidrBlock"],
            "availability_zone": subnet["AvailabilityZone"],
            "vpc_id": subnet["VpcId"],
            "total_ips": network.num_addresses,
            "usable_ips": usable,
            "in_use": len({k: v for k, v in ip_map.items() if not k.startswith("PREFIX:")}),
            "free": free,
        },
        "ip_addresses": entries,
    }
    return json.dumps(output, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze IP address usage in an AWS subnet.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python describe_subnet_contents.py --profile myprofile --subnet-id subnet-0abc123
  python describe_subnet_contents.py --profile myprofile --subnet-id subnet-0abc123 --output json
  python describe_subnet_contents.py --profile myprofile --subnet-id subnet-0abc123 --show-free
        """
    )
    parser.add_argument("--profile", required=True, help="AWS CLI profile name")
    parser.add_argument("--subnet-id", required=True, help="Subnet ID (e.g. subnet-0abc1234)")
    parser.add_argument(
        "--output", choices=["table", "json"], default="table",
        help="Output format: table (default) or json"
    )
    parser.add_argument(
        "--show-free", action="store_true",
        help="Include free/unallocated IPs in table output"
    )

    args = parser.parse_args()

    print(f"[*] Connecting with profile '{args.profile}'...")
    session = get_boto3_session(args.profile)

    print(f"[*] Fetching subnet '{args.subnet_id}'...")
    subnet = get_subnet(session, args.subnet_id)
    network = ipaddress.IPv4Network(subnet["CidrBlock"])

    print(f"[*] Scanning ENIs in subnet (CIDR: {subnet['CidrBlock']})...")
    ip_map = collect_eni_ips(session, args.subnet_id)

    reserved = get_aws_reserved_ips(network)

    print(f"[*] Found {len(ip_map)} allocated IPs.\n")

    if args.output == "json":
        print(format_json(subnet, network, ip_map, reserved))
    else:
        print(format_table(subnet, network, ip_map, reserved, args.show_free))


if __name__ == "__main__":
    main()
