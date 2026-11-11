"""
Firewall Rule Optimization - Mini Project
This program analyzes a simulated firewall rule list.
It does NOT change the operating system firewall.
"""

from dataclasses import dataclass, asdict
from typing import List, Tuple
import json


@dataclass(frozen=True)
class Rule:
    rule_id: int
    source_ip: str
    destination_port: int
    protocol: str
    action: str

    @classmethod
    def from_dict(cls, item):
        return cls(
            rule_id=int(item["rule_id"]),
            source_ip=str(item["source_ip"]),
            destination_port=int(item["destination_port"]),
            protocol=str(item["protocol"]).upper(),
            action=str(item["action"]).upper(),
        )


def validate_rule(rule: Rule) -> bool:
    """Validate fields in a simulated firewall rule."""
    import ipaddress

    try:
        ipaddress.ip_network(rule.source_ip, strict=False)
    except ValueError:
        return False

    return (
        1 <= rule.destination_port <= 65535
        and rule.protocol in {"TCP", "UDP", "ICMP", "ANY"}
        and rule.action in {"ALLOW", "DENY"}
    )


def load_rules(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as file:
        raw_rules = json.load(file)

    rules = [Rule.from_dict(item) for item in raw_rules]
    invalid = [r.rule_id for r in rules if not validate_rule(r)]
    if invalid:
        raise ValueError(f"Invalid rule ID(s): {invalid}")
    return rules


def rule_key(rule: Rule) -> Tuple:
    return (
        rule.source_ip,
        rule.destination_port,
        rule.protocol,
        rule.action,
    )


def remove_duplicates(rules: List[Rule]) -> Tuple[List[Rule], int]:
    """Keep the first occurrence of an exactly duplicated rule."""
    result = []
    seen = set()

    for rule in rules:
        key = rule_key(rule)
        if key not in seen:
            result.append(rule)
            seen.add(key)

    return result, len(rules) - len(result)


def find_conflicts(rules: List[Rule]) -> List[Tuple[Rule, Rule]]:
    """
    Report rules with the same source, port and protocol but
    different actions. These are potential conflicts.
    """
    conflicts = []
    for i, first in enumerate(rules):
        for second in rules[i + 1:]:
            same_match = (
                first.source_ip == second.source_ip
                and first.destination_port == second.destination_port
                and first.protocol == second.protocol
            )
            if same_match and first.action != second.action:
                conflicts.append((first, second))
    return conflicts


def optimize_rules(rules: List[Rule]) -> Tuple[List[Rule], int]:
    """
    Demonstration optimization:
    1. Remove exact duplicates.
    2. Sort rules by a stable match key, then DENY before ALLOW.
    This is a learning simulation, not a universally safe production
    firewall reordering algorithm.
    """
    unique, removed = remove_duplicates(rules)
    optimized = sorted(
        unique,
        key=lambda r: (
            r.source_ip,
            r.destination_port,
            r.protocol,
            0 if r.action == "DENY" else 1,
            r.rule_id,
        ),
    )
    return optimized, removed


def print_rules(title: str, rules: List[Rule]) -> None:
    print(f"\n{title}")
    print("-" * 76)
    print(f"{'ID':<5}{'SOURCE IP / NETWORK':<25}{'PORT':<9}{'PROTOCOL':<12}{'ACTION'}")
    print("-" * 76)
    for rule in rules:
        print(
            f"{rule.rule_id:<5}{rule.source_ip:<25}"
            f"{rule.destination_port:<9}{rule.protocol:<12}{rule.action}"
        )


def main():
    rules = load_rules("data/firewall_rules.json")
    print_rules("ORIGINAL FIREWALL RULES", rules)

    conflicts = find_conflicts(rules)
    print(f"\nPotential conflicts found: {len(conflicts)}")
    for first, second in conflicts:
        print(
            f"Rule {first.rule_id} ({first.action}) conflicts with "
            f"Rule {second.rule_id} ({second.action})"
        )

    optimized, removed = optimize_rules(rules)
    print_rules("OPTIMIZED FIREWALL RULES", optimized)
    print(f"\nDuplicate rules removed: {removed}")
    print(f"Rules before optimization: {len(rules)}")
    print(f"Rules after optimization:  {len(optimized)}")


if __name__ == "__main__":
    main()
