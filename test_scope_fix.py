#!/usr/bin/env python3
"""
Quick diagnostic to test the scope fix.
Run this before restarting the proxy to verify scope configuration.
"""

from talos.proxy.scope import in_scope, is_out_of_scope

# Test cases
test_hosts = [
    "example.com",
    "api.example.com",
    "sub.api.example.com",
    "other.com",
]

# Replace with your actual project scope patterns
test_scope = [
    "example.com",
    "*.api.example.com",
]

print("=" * 60)
print("SCOPE FIX DIAGNOSTIC")
print("=" * 60)
print(f"\nConfigured scope: {test_scope}\n")

print("Testing in_scope() function:")
print("-" * 60)
for host in test_hosts:
    result = in_scope(host, test_scope)
    status = "✓ IN SCOPE" if result else "✗ OUT OF SCOPE"
    print(f"{host:30} -> {status}")

print("\n" + "=" * 60)
print("✓ If in_scope() returns bool (not None), the fix is working!")
print("=" * 60)

# Test is_out_of_scope
test_blocked = frozenset(["blocked.com", "nope.example.com"])
print(f"\nTesting is_out_of_scope() with blocked: {test_blocked}\n")
for host in test_hosts + ["blocked.com", "sub.blocked.com"]:
    result = is_out_of_scope(host, test_blocked)
    status = "✓ BLOCKED" if result else "✗ ALLOWED"
    print(f"{host:30} -> {status}")
