#!/usr/bin/env python3

import sys
from obscura.process_manager import get_process_manager

try:
    pm = get_process_manager()
    print('[SUCCESS] ProcessManager initialized successfully')
    print(f'Process counts: {pm.get_process_count()}')
    
    from obscura.attacks import AttackOrchestrator
    orch = AttackOrchestrator('wlan0', simulate_mode=True)
    print('[SUCCESS] AttackOrchestrator initialized with ProcessManager')
    print(f'Orchestrator has process_manager: {hasattr(orch, "process_manager")}')
    
    counts = orch.process_manager.get_process_count()
    print(f'[SUCCESS] Process counts from orchestrator: {counts}')
    
    print('\n[PASS] All ProcessManager integration tests passed!')
    sys.exit(0)
    
except Exception as e:
    print(f'[FAIL] Error: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
