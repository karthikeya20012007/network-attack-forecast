import subprocess
import os

def test_explicit_network_interface():
    # Run the script with dry-run or just grep it
    # We can inspect start_cic.sh to ensure it uses $NETWORK_INTERFACE or eth0
    script_path = "scripts/start_cic.sh"
    with open(script_path, "r") as f:
        content = f.read()
    
    assert 'INTERFACE="${1:-${NETWORK_INTERFACE:-eth0}}"' in content, "Should fallback to eth0 if NETWORK_INTERFACE is not set"
    assert "veth-target" not in content, "Should not hardcode veth-target"
    assert "eth2" not in content, "Should not hardcode eth2"

def test_redis_host():
    env_path = ".env"
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            content = f.read()
        assert "REDIS_HOST=127.0.0.1" in content, "REDIS_HOST should be local 127.0.0.1"

