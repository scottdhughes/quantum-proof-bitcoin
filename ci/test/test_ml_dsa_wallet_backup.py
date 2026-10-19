#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Data-only policy tests: never build or load the new native prototype."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
RUNNER=ROOT/"contrib/ml-dsa-wallet-backup/run_backup_tests.py"


class WalletBackupRunnerTests(unittest.TestCase):
    def module(self):
        spec=importlib.util.spec_from_file_location("backup_runner",RUNNER)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def fixture(self, root):
        for directory in ("contrib/ml-dsa-engineering", "contrib/ml-dsa-key-lifecycle"):
            shutil.copytree(ROOT/directory,root/directory,ignore=shutil.ignore_patterns("__pycache__"))
        for name in ("contrib/ml-dsa-ref/review_baseline_commit.txt", "contrib/shrincs/manifest.json"):
            dest=root/name; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(ROOT/name,dest)

    def test_exact_frozen_sources_accepted(self):
        self.assertEqual(self.module().validate_sources(ROOT), {
            "result":"PASS","capsule_sha256":"2588da55bcd4443aea906bf16fe21402d8d5ee4b19be906e3f72c563b81601bb",
            "key_module_files":6,"controls_frozen":True})

    def tamper(self, name, mode):
        module=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root); path=root/name
            if mode=="append": path.write_bytes(path.read_bytes()+b"\n/* substituted */\n")
            elif mode=="remove": path.unlink()
            elif mode=="symlink":
                data=path.read_bytes(); target=root/"outside"; target.write_bytes(data); path.unlink(); path.symlink_to(target)
            with self.assertRaises(module.HarnessError): module.validate_sources(root)

    def test_key_implementation_substitution_rejected(self): self.tamper("contrib/ml-dsa-key-lifecycle/key_lifecycle.c","append")
    def test_frozen_preflight_reader_substitution_rejected(self): self.tamper("contrib/ml-dsa-key-lifecycle/run_key_lifecycle_tests.py","append")
    def test_missing_key_input_rejected(self): self.tamper("contrib/ml-dsa-key-lifecycle/key_lifecycle.h","remove")
    def test_symlink_key_input_rejected(self): self.tamper("contrib/ml-dsa-key-lifecycle/exports.map","symlink")
    def test_guarded_wrapper_substitution_rejected(self): self.tamper("contrib/ml-dsa-engineering/pqbtc_mldsa44.c","append")
    def test_modified_manifest_cannot_authorize_capsule(self): self.tamper("contrib/ml-dsa-engineering/vendor/mldsa-native/SOURCE.json","append")
    def test_backend_control_change_rejected(self): self.tamper("contrib/ml-dsa-engineering/backend_admission.json","append")
    def test_shrincs_control_change_rejected(self): self.tamper("contrib/shrincs/manifest.json","append")
    def test_baseline_pointer_change_rejected(self): self.tamper("contrib/ml-dsa-ref/review_baseline_commit.txt","append")

    def test_missing_and_extra_exports_rejected(self):
        module=self.module()
        for actual in (module.EXPECTED_EXPORTS-{"pqbtc_backup_restore"},module.EXPECTED_EXPORTS|{"pqbtc_backup_test_stage"},module.EXPECTED_EXPORTS|{"pqbtc_mldsa44_sign_hedged"}):
            with self.subTest(actual=actual),self.assertRaises(module.HarnessError): module.require_exports(actual)

    def test_normal_exports_accepted(self):
        module=self.module(); self.assertIsNone(module.require_exports(module.EXPECTED_EXPORTS))

    def test_incomplete_or_wrong_runtime_native_reports_rejected(self):
        module=self.module()
        for text in ("", "backup smoke: PASS (1368 checks)\n", "backup crypto runtime: OpenSSL 3.0.22\nbackup smoke: PASS (1368 checks)\n", "backup crypto runtime: OpenSSL 3.6.5 29 Sep 2026\nbackup smoke: PASS (1367 checks)\n", "backup crypto runtime: OpenSSL 3.6.5 29 Sep 2026\nbackup smoke: PASS (808 checks)\n"):
            with self.subTest(text=text),self.assertRaises(module.HarnessError): module.smoke_result(text,"codec")
        with self.assertRaises(module.HarnessError): module.smoke_result("backup file smoke: PASS (1033 checks)\n","file")

    def test_complete_report_accepted(self):
        self.assertEqual(self.module().smoke_result("backup crypto runtime: OpenSSL 3.6.5 29 Sep 2026\nbackup smoke: PASS (1368 checks)\n","codec"),{"result":"PASS","checks":1368})

    def test_unrelated_failure_does_not_qualify_negative_control(self):
        module=self.module()
        for kind in ("wipe","authentication","aad","policy"):
            for code,error in ((0,""),(139,"crash"),(1,"unrelated failure")):
                with self.subTest(kind=kind,code=code),self.assertRaises(module.HarnessError): module.require_control(kind,code,error)

    def test_policy_control_requires_the_policy_rejection_assertion(self):
        module=self.module()
        marker="pqbtc_pilot_verify(policy_signature,2420,public_key,1312,intent,112,challenge)==PQBTC_BACKUP_AUTH"
        module.require_control("policy",1,"FAIL: /tmp/smoke.c:123: "+marker+"\n")
        for code,error in ((0,""),(139,"crash"),(1,"FAIL: /tmp/smoke.c:123: unrelated\n")):
            with self.subTest(code=code),self.assertRaises(module.HarnessError): module.require_control("policy",code,error)

    def test_wrong_openssl_source_marker_rejected_before_native_execution(self):
        module=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/"source-archive.sha256").write_text("0"*64+"\n")
            with self.assertRaises(module.HarnessError): module.validate_openssl(root)

    def test_wrong_or_dirty_runtime_cannot_be_trusted_head(self):
        module=self.module()
        with self.assertRaises(module.HarnessError): module.runtime_identity("0"*40,ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/"input").write_text("public fixture\n")
            for args in (("init","-q"),("add","input"),("-c","user.name=Public Test","-c","user.email=public-test@example.invalid","commit","-qm","public fixture")):
                subprocess.run(["git","-C",str(root),*args],check=True,capture_output=True)
            head=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
            self.assertEqual(module.runtime_identity(head,root),{"commit":head,"worktree":"clean"})
            (root/"input").write_text("modified public fixture\n")
            with self.assertRaises(module.HarnessError): module.runtime_identity(head,root)
            (root/"input").write_text("public fixture\n"); (root/"untracked").write_text("public\n")
            with self.assertRaises(module.HarnessError): module.runtime_identity(head,root)

    def test_missing_phase_stdout_cannot_qualify_a_process_report(self):
        module=self.module()
        phases=[{"phase":p,"pid":i+10,"zero_value_only":True} for i,p in enumerate(("challenge","produce","restore-sign","verify"))]
        report={"result":"PASS","checks":16,"phases":phases,"commands":[
            {"command":["/tmp/demo","verify","/tmp/public"],"returncode":0 if i in (0,1,3,4) else 1,
             "stdout":"","stderr":"" if i in (0,1,3,4) else "zero-value pilot phase rejected\n"} for i in range(16)]}
        with self.assertRaises(module.HarnessError): module.process_result(json.dumps(report))

    def test_preflight_cli_is_data_only_and_creates_no_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"not-created"
            result=subprocess.run([sys.executable,str(RUNNER),"--preflight-only","--output-dir",str(output)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('"result": "PASS"',result.stdout)
            self.assertFalse(output.exists())


if __name__=="__main__": unittest.main()
