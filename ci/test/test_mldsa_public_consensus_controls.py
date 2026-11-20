"""Receipt closure for actual public-profile accepted-set/reindex controls."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "contrib/ml-dsa-qualification/public_consensus_controls.py"


class PublicConsensusReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = None
        if DRIVER.is_file():
            spec = importlib.util.spec_from_file_location("public_consensus_control_tests", DRIVER)
            cls.driver = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.driver)

    def receipt(self):
        self.assertIsNotNone(self.driver, "Repeatable actual public consensus driver is missing")
        state = {"tip": "ab" * 32, "height": 106,
                 "utxo": {"height": 106, "bestblock": "ab" * 32, "txouts": 107,
                          "total_amount": "5099.9992", "muhash": "cd" * 32}}
        rows = []
        for name in self.driver.CONTROL_NAMES:
            if name in self.driver.POSITIVE_CONTROLS:
                row = {"control": name, "testmempoolaccept": {"allowed": True}, "submitblock": None}
            else:
                reason = "bad-mldsa44-prevout" if name == "nonempty_scriptSig" else "bad-mldsa44-output"
                if name == "actual_wrong_network_signature":
                    reason = "mandatory-script-verify-flag-failed"
                row = {"control": name, "testmempoolaccept": {"allowed": False, "reject-reason": reason},
                       "submitblock": reason, "tip_unchanged": True}
            if name.startswith("reindex"):
                row["state"] = copy.deepcopy(state)
                row["rejected_block_hash"] = "ee" * 32 if name.startswith("reindex-chainstate") else "ff" * 32
            if name == "reindex_full_history_and_native_rejection":
                row["revisited_stored_block_hash"] = "ee" * 32
                row["stored_rejection_log_line"] = "ConnectTip: ConnectBlock " + "ee" * 32 + " failed, bad-mldsa44-output"
                row["fresh_reindex_log_sha256"] = "12" * 32
            rows.append(row)
        return {"schema": self.driver.SCHEMA, "scope": self.driver.SCOPE, "result": "PASS",
                "binary_sha256": "34" * 32, "owned_node_cleanup": "STOPPED",
                "state_before_reindex": state, "observations": rows}

    def test_complete_control_receipt_is_accepted(self):
        self.driver_required().validate_report(self.receipt())

    def driver_required(self):
        self.assertIsNotNone(self.driver, "Repeatable actual public consensus driver is missing")
        return self.driver

    def test_missing_duplicate_or_wrong_network_control_cannot_be_passing(self):
        driver = self.driver_required()
        receipt = self.receipt()
        missing = copy.deepcopy(receipt)
        missing["observations"].pop()
        duplicate = copy.deepcopy(receipt)
        duplicate["observations"][-1] = duplicate["observations"][0]
        wrong = copy.deepcopy(receipt)
        row = next(row for row in wrong["observations"] if row["control"] == "actual_wrong_network_signature")
        row["testmempoolaccept"] = {"allowed": True}
        row["submitblock"] = None
        for value in (missing, duplicate, wrong):
            with self.subTest(value=value["observations"][-1]["control"]), self.assertRaises(ValueError):
                driver.validate_report(value)

    def test_tip_only_agreement_or_unjoined_reindex_log_cannot_be_passing(self):
        driver = self.driver_required()
        baseline = self.receipt()
        values = []
        changed_utxo = copy.deepcopy(baseline)
        changed_utxo["observations"][-1]["state"]["utxo"]["muhash"] = "00" * 32
        values.append(changed_utxo)
        for field, value in (("revisited_stored_block_hash", "00" * 32),
                             ("stored_rejection_log_line", "unrelated bad-mldsa44-output"),
                             ("fresh_reindex_log_sha256", None)):
            invalid = copy.deepcopy(baseline)
            invalid["observations"][-1][field] = value
            values.append(invalid)
        values.append({**baseline, "owned_node_cleanup": "FORCED"})
        for index, value in enumerate(values):
            with self.subTest(index=index), self.assertRaises(ValueError):
                driver.validate_report(value)


if __name__ == "__main__":
    unittest.main()
