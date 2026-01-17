import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from obscura.attack_plugins import sdr_attacks

reg = sdr_attacks.register_attack()
print('Module:', reg['name'])
print('Attacks:', list(reg['attacks'].keys()))
print('Hardware Detection:', callable(reg['hardware_detection']))
print('All functions callable:', all(callable(f) for f in reg['attacks'].values()))
