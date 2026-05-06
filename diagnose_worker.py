#!/usr/bin/env python3
"""
Diagnostic script to check if the worker is running and processing flows.
Run this while the proxy is active.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from talos.proxy.queue import flow_queue
from talos.config import TalosConfig
from talos.projects.manager import ProjectManager

def main():
    config = TalosConfig.from_env()
    manager = ProjectManager(projects_root=config.projects_dir)
    project = manager.active()
    
    if not project:
        print("❌ No active project")
        return
    
    print(f"✓ Active project: {project.id}")
    print(f"✓ Scope: {project.scope}")
    print(f"✓ DB path: {project.db_path}")
    print(f"✓ DB exists: {project.db_path.exists()}")
    print()
    
    # Check queue state
    print("Queue status:")
    print(f"  Queue size: {flow_queue._q.qsize()}")
    print(f"  Max size: {flow_queue._q.maxsize}")
    print(f"  Dropped flows: {flow_queue.dropped_flow_count}")
    print()
    
    # Test scope matching
    from talos.proxy.scope import in_scope
    test_hosts = [
        "www.google.com",
        "google.com",
        "mail.google.com",
        "www.youtube.com",
    ]
    
    print("Scope matching test:")
    for host in test_hosts:
        result = in_scope(host, project.scope)
        status = "✓ IN SCOPE" if result else "✗ OUT OF SCOPE"
        print(f"  {host:25} -> {status}")
    print()
    
    # Check database
    import sqlite3
    conn = sqlite3.connect(str(project.db_path))
    flow_count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    endpoint_count = conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
    role_count = conn.execute("SELECT COUNT(*) FROM roles").fetchone()[0]
    module_count = conn.execute("SELECT COUNT(*) FROM modules").fetchone()[0]
    conn.close()
    
    print("Database state:")
    print(f"  Flows: {flow_count}")
    print(f"  Endpoints: {endpoint_count}")
    print(f"  Roles: {role_count}")
    print(f"  Modules: {module_count}")
    print()
    
    # Watch queue for 10 seconds
    print("Watching queue for 10 seconds...")
    print("(Capture some traffic in your browser now)")
    start_size = flow_queue._q.qsize()
    time.sleep(10)
    end_size = flow_queue._q.qsize()
    
    print(f"  Queue size change: {start_size} -> {end_size}")
    if end_size > start_size:
        print("  ✓ Flows are being enqueued!")
    elif start_size == end_size == 0:
        print("  ❌ No flows enqueued (scope issue or proxy not capturing)")
    else:
        print(f"  ⚠ Queue drained {start_size - end_size} flows (worker is active)")

if __name__ == "__main__":
    main()
