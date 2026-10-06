import json
import os
import tempfile
import unittest

from predict import json_to_features


class JsonToFeaturesTests(unittest.TestCase):
    def _write_json(self, payload):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(payload, tmp)
        tmp.close()
        self.addCleanup(lambda: os.unlink(tmp.name))
        return tmp.name

    def test_defaults_when_fields_are_missing(self):
        path = self._write_json({})
        df = json_to_features(path)
        row = df.iloc[0].to_dict()

        self.assertEqual(row["num_permissions"], 0)
        self.assertEqual(row["num_dangerous_permissions"], 0)
        self.assertEqual(row["num_activities"], 0)
        self.assertEqual(row["num_services"], 0)
        self.assertEqual(row["num_receivers"], 0)
        self.assertEqual(row["is_signed"], 0)
        self.assertEqual(row["risk_score"], 0)

    def test_counts_dangerous_permissions_and_components(self):
        path = self._write_json(
            {
                "permissions": [
                    "android.permission.READ_SMS",
                    "android.permission.INTERNET",
                    "android.permission.SEND_SMS",
                ],
                "activities": ["A1", "A2"],
                "services": ["S1"],
                "receivers": ["R1", "R2", "R3"],
                "is_signed": True,
                "risk_score": 9,
            }
        )
        df = json_to_features(path)
        row = df.iloc[0].to_dict()

        self.assertEqual(row["num_permissions"], 3)
        self.assertEqual(row["num_dangerous_permissions"], 2)
        self.assertEqual(row["num_activities"], 2)
        self.assertEqual(row["num_services"], 1)
        self.assertEqual(row["num_receivers"], 3)
        self.assertEqual(row["is_signed"], 1)
        self.assertEqual(row["risk_score"], 9)


if __name__ == "__main__":
    unittest.main()
