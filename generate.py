import json
import os
import sys

sys.path.insert(0, os.path.abspath('.'))

from app.core import rules_builder
from app.services import domain_service

with open('config/project_m.example.json', 'r') as f:
    config = json.load(f)

config['clisrv']['enabled'] = True
config['mac_rules'] = [
    {"name": "Client1", "mac": "00:11:22:33:44:55", "interface": "eth1", "enabled": True}
]

resolved = domain_service.resolve_all_domains(config.get("blocked_domains", {}))
rules_content = rules_builder.build_rules(config, resolved)

with open('rules/project_m.rules.v4', 'w', encoding='utf-8') as f:
    f.write(rules_content)

print("Rules generated successfully.")
