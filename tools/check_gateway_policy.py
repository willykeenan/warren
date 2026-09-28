import pathlib, subprocess, tempfile
root=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="gateway-check-",dir=root) as tmp:
 out=pathlib.Path(tmp)/"policy-tests"
 subprocess.run(["rustc","--edition=2021","--test",str(root/"src/gateway_policy.rs"),"-o",str(out)],check=True)
 subprocess.run([str(out)],check=True,timeout=45)
print("CHECK_PASS:gateway-policy")
