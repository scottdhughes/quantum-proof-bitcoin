#!/usr/bin/env python3
"""Isolated copies only: portable stdlib positive and negative packet controls."""
if not __debug__:
    raise SystemExit("Optimized Python refused")
import json,os,shutil,stat,subprocess,sys,tempfile,types
from pathlib import Path
ROOT=Path(__file__).absolute().parent
fd=os.open(ROOT.anchor,os.O_RDONLY|os.O_DIRECTORY)
try:
    for part in ROOT.parts[1:]:
        nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        os.close(fd);fd=nxt
    source_fd=os.open("verify.py",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
finally:os.close(fd)
try:
    info=os.fstat(source_fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>1024*1024:raise ValueError("Unsafe verifier source")
    source=b""
    while part:=os.read(source_fd,65536):source+=part
finally:os.close(source_fd)
v=types.ModuleType("portable_l_selected_verifier");v.__file__=str(ROOT/"verify.py")
exec(compile(source,v.__file__,"exec"),v.__dict__)

def require(ok,message):
    if not ok:raise ValueError(message)

def main():
    work=Path(tempfile.mkdtemp(prefix=".verification-work-",dir=ROOT))
    results=[]
    try:
        sealed=v.checksum_map(v.safe_read(ROOT,"sha256sums"))
        names=sorted(set(sealed)|{"sha256sums"})
        minimal_env={"PATH":"/usr/bin:/bin","HOME":str(work/"empty-home"),"LANG":"C","PYTHONOPTIMIZE":"1"}
        (work/"empty-home").mkdir()
        def copy_packet(name):
            destination=work/name;destination.mkdir()
            for member in names:
                raw=v.safe_read(ROOT,member)
                if member in sealed:require(v.sha(raw)==sealed[member],"source checksum mismatch before copy")
                p=destination/member;p.parent.mkdir(parents=True,exist_ok=True)
                fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                try:
                    offset=0
                    while offset<len(raw):offset+=os.write(fd,raw[offset:])
                finally:os.close(fd)
            return destination
        def execute(case,optimized=False):
            argv=[sys.executable,"-I"]+(["-O"] if optimized else [])+["-B",str(case/"verify.py")]
            return subprocess.run(argv,cwd=work,env=minimal_env,capture_output=True,text=True,timeout=30)
        def reseal(case,changed,inventory_member=None):
            if inventory_member:
                name=inventory_member;original=case/"native-l/linux-aarch64-gcc/native-qualification/evidence-sha256.json"
                inventory=json.loads(original.read_bytes());inventory[name]=v.sha((case/changed).read_bytes());original.write_text(json.dumps(inventory,sort_keys=True,indent=2)+"\n")
            index_path=case/"source.json";index=json.loads(index_path.read_bytes())
            for row in index["files"]:
                raw=(case/row["path"]).read_bytes();row["sha256"]=v.sha(raw);row["bytes"]=len(raw)
                if row["transform"]=="NONE":row["origin_sha256"]=v.sha(raw);row["origin_bytes"]=len(raw)
            index_path.write_text(json.dumps(index,sort_keys=True,indent=2)+"\n")
            (case/"sha256sums").write_text("".join(v.sha((case/name).read_bytes())+"  "+name+"\n" for name in sorted(sealed)))
        baseline=copy_packet("relocated-positive")
        result=execute(baseline)
        require(result.returncode==0 and json.loads(result.stdout)["result"]=="VERIFIED_SELECTED_L4_NATIVE_PRIVATE_HTTP_AND_CI","relocated minimal-env positive failed: "+result.stderr[:300])
        results.append({"name":"relocated_minimal_environment_positive","result":"PASS","isolated_PYTHONOPTIMIZE_ignored":True,"native_or_network_execution":False})
        result=execute(baseline,optimized=True)
        require(result.returncode!=0 and "Optimized Python refused" in result.stderr,"optimized interpreter false PASS")
        results.append({"name":"explicit_optimized_interpreter_refused","result":"PASS"})
        case=copy_packet("tamper");(case/"context/root-four-profile-reverification.json").write_bytes((case/"context/root-four-profile-reverification.json").read_bytes()+b" ")
        result=execute(case);require(result.returncode!=0 and "Packet checksum mismatch" in result.stderr,"file tamper accepted");results.append({"name":"file_tamper_rejected","result":"PASS","checksum_rebuilt":False})
        native_path="native-l/linux-aarch64-gcc/native-qualification/"
        app_path="native-l/linux-aarch64-gcc/public-profile-app/report.json"
        mutations=[
          ("wrong_L_HEAD",native_path+"report.json",lambda x:x["source"].update(head="0"*40),"Native source binding","report.json"),
          ("wrong_app_manifest",app_path,lambda x:x.update(manifest_sha256="0"*64),"Image/manifest binding",None),
          ("app_cleanup_error",app_path,lambda x:x.update(cleanup_errors=["synthetic cleanup failure"]),"Private HTTP app outcome/scope",None),
          ("short_native_gates",native_path+"report.json",lambda x:x["checks"].pop("signer-normal"),"All nine native gates","report.json"),
          ("short_resource_samples",native_path+"node-resources.json",lambda x:x["samples"].pop(),"Thirty actual full-weight","node-resources.json"),
          ("short_consensus_controls",native_path+"public-consensus-controls.json",lambda x:x["observations"].pop(),"All sixteen actual public consensus","public-consensus-controls.json"),
          ("reissued_payment_claim",app_path,lambda x:x["events"][6].update(reissued_payment=True),"Same-id rebroadcast proof",None),
          ("orphan_network_resumed",app_path,lambda x:x["events"][11].update(network_active=True),"Conservative peer-policy recovery proof",None),
        ]
        for name,member,mutate,reason,inventory in mutations:
            case=copy_packet(name);p=case/member;value=json.loads(p.read_bytes());mutate(value);p.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n");reseal(case,member,inventory)
            result=execute(case);require(result.returncode!=0 and reason in result.stderr,name+" semantic mutant accepted or wrong gate: "+result.stderr[:250]);results.append({"name":name+"_semantic_rejection","result":"PASS","checksums_and_index_rebuilt":True,"selected_native_inventory_updated":inventory is not None,"expected_gate":reason})
        external=work/"public-marker";external.mkdir();(external/"marker.json").write_text('{"public_marker":true}\n')
        case=copy_packet("directory-symlink");shutil.rmtree(case/"native-l");(case/"native-l").symlink_to(external,target_is_directory=True)
        result=execute(case);require(result.returncode!=0 and "symlink" in result.stderr.lower(),"directory symlink accepted");results.append({"name":"directory_symlink_rejected_without_recursing","result":"PASS"})
        try:v.safe_read(case,"native-l/marker.json")
        except (OSError,ValueError):pass
        else:raise ValueError("copy/read gate followed a directory symlink")
        results.append({"name":"copy_and_open_directory_symlink_gate","result":"PASS"})
        case=copy_packet("file-symlink");p=case/app_path;p.unlink();p.symlink_to(external/"marker.json")
        result=execute(case);require(result.returncode!=0 and "symlink" in result.stderr.lower(),"file symlink accepted");results.append({"name":"file_symlink_rejected","result":"PASS"})
        root_link=work/"root-link";root_link.symlink_to(baseline,target_is_directory=True)
        result=subprocess.run([sys.executable,"-I","-B",str(baseline/"verify.py"),str(root_link)],cwd=work,env=minimal_env,capture_output=True,text=True,timeout=30)
        require(result.returncode!=0,"root path component symlink accepted");results.append({"name":"root_symlink_component_rejected","result":"PASS"})
        return {"schema":"PQBTC-L-PORTABLE-PACKET-CONTROLS-1","result":"PASS","controls":results,"control_count":len(results),"verifier_sha256":v.sha(v.safe_read(ROOT,"verify.py")),"python_implementation":sys.implementation.name,"python_version":list(sys.version_info[:3]),"scope":"DERIVED_TEST_RECEIPT_ONLY_NO_NATIVE_OR_NETWORK_OPERATIONS","original_payloads_modified":False,"relocated_stdlib_minimal_environment":True,"public_soak_credit_seconds":0}
    finally:
        require(work.parent==ROOT and work.name.startswith(".verification-work-"),"unsafe test cleanup")
        shutil.rmtree(work)
if __name__=="__main__":
    try:print(json.dumps(main(),sort_keys=True))
    except Exception as error:print("CONTROLS_FAILED: "+str(error),file=sys.stderr);sys.exit(1)
