#!/usr/bin/env python3
"""
Unit tests for the Automated PR Code Review Bot
"""

import unittest
from code_review import parse_diff_lines, analyze_with_static_rules, generate_markdown_report

SAMPLE_DIFF = """diff --git a/UserController.cs b/UserController.cs
new file mode 100644
index 0000000..1d0ce0b
--- /dev/null
+++ b/UserController.cs
@@ -0,0 +1,18 @@
+using System;
+
+public class UserController
+{
+    // HATA 1: Şifre kodun içine açıkça yazılmış
+    private string dbPassword = "SuperSecretPassword123!";
+
+    public void GetUser(string userId)
+    {
+        // HATA 2: SQL Injection açığı
+        string query = "SELECT * FROM Users WHERE Id = " + userId;
+        Console.WriteLine("Sorgu çalıştırılıyor: " + query);
+
+        // HATA 3: Null kontrolü yok
+        string name = null;
+        Console.WriteLine(name.ToUpper());
+    }
+}
+"""

class TestCodeReviewBot(unittest.TestCase):

    def test_parse_diff_lines(self):
        parsed = parse_diff_lines(SAMPLE_DIFF)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["file"], "UserController.cs")
        self.assertGreater(len(parsed[0]["lines"]), 10)

    def test_detect_hardcoded_password(self):
        parsed = parse_diff_lines(SAMPLE_DIFF)
        issues = analyze_with_static_rules(parsed)
        secrets = [i for i in issues if "Hardcoded Secret" in i.message]
        self.assertTrue(len(secrets) >= 1)
        self.assertEqual(secrets[0].severity, "CRITICAL")
        self.assertEqual(secrets[0].line_no, 6)

    def test_detect_sql_injection(self):
        parsed = parse_diff_lines(SAMPLE_DIFF)
        issues = analyze_with_static_rules(parsed)
        sqli = [i for i in issues if "SQL Injection" in i.message]
        self.assertTrue(len(sqli) >= 1)
        self.assertEqual(sqli[0].severity, "CRITICAL")
        self.assertEqual(sqli[0].line_no, 11)

    def test_detect_null_reference(self):
        parsed = parse_diff_lines(SAMPLE_DIFF)
        issues = analyze_with_static_rules(parsed)
        null_issues = [i for i in issues if "NullReferenceException" in i.message]
        self.assertTrue(len(null_issues) >= 1)
        self.assertEqual(null_issues[0].severity, "CRITICAL")
        self.assertEqual(null_issues[0].line_no, 16)

    def test_clean_code_passes(self):
        clean_diff = """diff --git a/CleanService.cs b/CleanService.cs
new file mode 100644
--- /dev/null
+++ b/CleanService.cs
@@ -0,0 +1,5 @@
+public class CleanService
+{
+    public int CalculateSum(int a, int b) => a + b;
+}
+"""
        parsed = parse_diff_lines(clean_diff)
        issues = analyze_with_static_rules(parsed)
        critical_issues = [i for i in issues if i.severity == "CRITICAL"]
        self.assertEqual(len(critical_issues), 0)

    def test_report_generation(self):
        parsed = parse_diff_lines(SAMPLE_DIFF)
        issues = analyze_with_static_rules(parsed)
        report = generate_markdown_report(issues, ai_review=None, has_gemini_key=False)
        self.assertIn("Otomatik Kod İnceleme Raporu", report)
        self.assertIn("KRİTİK", report)
        self.assertIn("SQL Injection", report)

if __name__ == "__main__":
    unittest.main()
