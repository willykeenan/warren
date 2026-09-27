import pathlib,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1]
subprocess.run([sys.executable,"-m","unittest","discover","-s","tests","-p","test_gateway_discovery.py","-v"],cwd=root,check=True,timeout=90)
sys.path.insert(0,str(root))
from gateway_connector.discovery import build_public_summary
assert build_public_summary([{"address":"192.168.1.2","name":"PRIVATE","password":"DO_NOT_LEAK"}]) == {"attached_device_count":1}
print("CHECK_PASS:gateway-discovery")
