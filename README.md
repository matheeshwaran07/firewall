# Firewall Rule Optimization

## 1. Project Overview
Firewall Rule Optimization is a Python mini project that analyzes a sample firewall rule list and demonstrates basic rule cleanup. It identifies duplicate rules, reports potential conflicting rules, and produces an organized rule list.

**Important:** This is a safe educational simulation. It does not modify Windows, Linux, router, or production firewall settings.

## 2. Objectives
- Store firewall rules in a structured JSON file.
- Validate IP addresses, ports, protocols, and actions.
- Detect duplicate rules.
- Identify rules that match the same traffic but have different actions.
- Generate an optimized demonstration rule list.

## 3. Technologies Used
- Python 3
- JSON
- Python standard library (`ipaddress`, `json`, `unittest`, `dataclasses`)

No external packages are required.

## 4. Project Structure
```text
firewall-rule-optimization/
├── data/
│   └── firewall_rules.json
├── src/
│   └── firewall_optimizer.py
├── tests/
│   └── test_firewall_optimizer.py
└── README.md
```

## 5. How to Run
1. Install Python 3.
2. Download or clone this repository.
3. Open a terminal in the project folder.
4. Run:

```bash
python src/firewall_optimizer.py
```

## 6. Run Unit Tests
```bash
python -m unittest discover -s tests -v
```

## 7. Sample Output
The program displays:
- Original firewall rules
- Number of potential conflicts
- Conflicting rule IDs and actions
- Optimized rule list
- Number of duplicate rules removed
- Rule count before and after optimization

## 8. Optimization Logic
1. Validate each rule.
2. Compare rules to identify exact duplicates.
3. Keep only the first copy of each duplicate.
4. Report same-match rules with different actions as potential conflicts.
5. Sort the remaining rules by source, port, protocol, and action.

This sorting is only a demonstration. Real firewalls may use first-match or other vendor-specific policies, so changing rule order can change security behavior. Production rules must be reviewed and tested by an administrator before deployment.

## 9. Future Enhancements
- Add a graphical user interface.
- Import and export CSV files.
- Support rule priority and first-match simulation.
- Add a rule search and filtering feature.
- Generate an optimization report.

## 10. Author
Student Mini Project
