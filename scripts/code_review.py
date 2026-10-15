#!/usr/bin/env python3
"""
Automated Code Review Bot
-------------------------
Inspects git diff between branches (e.g. PR branch vs base branch),
performs security vulnerability detection, crash/reliability analysis,
and clean code checks. Supports both deterministic rule-based analysis
and Gemini AI-powered deep review (when GEMINI_API_KEY is available).
"""

import os
import sys
import json
import re
import subprocess
import argparse
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional, Tuple

BOT_SIGNATURE = "<!-- automated-code-review-bot -->"

class Issue:
    def __init__(self, severity: str, category: str, file_path: str, line_no: Optional[int], message: str, code_snippet: str = ""):
        self.severity = severity  # 'CRITICAL', 'WARNING', 'INFO'
        self.category = category  # 'Güvenlik Açığı', 'Çökme Riski', 'Temiz Kod'
        self.file_path = file_path
        self.line_no = line_no
        self.message = message
        self.code_snippet = code_snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "file_path": self.file_path,
            "line_no": self.line_no,
            "message": self.message,
            "code_snippet": self.code_snippet
        }


def run_command(cmd: List[str]) -> Tuple[int, str, str]:
    """Runs a shell command and returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return 1, "", str(e)


def get_git_diff(base: str, head: str, diff_file: Optional[str] = None) -> str:
    """Extracts git diff between base and head or from a specified diff file."""
    if diff_file and os.path.exists(diff_file):
        with open(diff_file, "r", encoding="utf-8") as f:
            return f.read()

    # Generate candidate ref pairs (e.g. origin/main vs main)
    base_candidates = [base]
    if base.startswith("origin/"):
        base_candidates.append(base[7:])
    else:
        base_candidates.append(f"origin/{base}")

    head_candidates = [head]
    if head.startswith("origin/"):
        head_candidates.append(head[7:])

    for b in base_candidates:
        for h in head_candidates:
            # Try triple-dot diff first (merge-base diff)
            code, stdout, _ = run_command(["git", "diff", f"{b}...{h}"])
            if code == 0 and stdout.strip():
                return stdout

            # Fallback to double-dot diff
            code, stdout, _ = run_command(["git", "diff", f"{b}..{h}"])
            if code == 0 and stdout.strip():
                return stdout

    for b in base_candidates:
        # If comparing to HEAD directly or working tree
        code, stdout, _ = run_command(["git", "diff", b])
        if code == 0 and stdout.strip():
            return stdout

    return ""


def parse_diff_lines(diff_text: str) -> List[Dict[str, Any]]:
    """
    Parses git unified diff into structured file entries with added/modified lines
    and their target line numbers.
    """
    files = []
    current_file = None
    current_lines = []
    current_target_line = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            if current_file:
                files.append({"file": current_file, "lines": current_lines})
            current_file = None
            current_lines = []
        elif line.startswith("+++ b/"):
            current_file = line[6:].strip()
        elif line.startswith("@@"):
            # Format: @@ -start,count +start,count @@
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if match:
                current_target_line = int(match.group(1))
        elif current_file:
            if line.startswith("+") and not line.startswith("+++"):
                current_lines.append((current_target_line, line[1:]))
                current_target_line += 1
            elif not line.startswith("-"):
                current_target_line += 1

    if current_file:
        files.append({"file": current_file, "lines": current_lines})

    return files


def analyze_with_static_rules(parsed_files: List[Dict[str, Any]]) -> List[Issue]:
    """
    Deterministic static security & code quality checks.
    Detects hardcoded secrets, SQL injection, null dereferences, logging anti-patterns, etc.
    """
    issues: List[Issue] = []

    # Regex patterns for static rules
    secret_patterns = [
        (re.compile(r'(?i)(password|passwd|pwd|secret|api_key|apikey|token|private_key|auth_token)\s*=\s*["\']([^"\']{6,})["\']'),
         "Açık Metin Parola/Gizli Bilgi (Hardcoded Secret)",
         "Hassas kimlik bilgisi (şifre/API anahtarı) kaynak koda açıkça yazılmış. Bu değerleri ortam değişkenleri (Environment Variables) veya Secret Manager ile yönetin."),
    ]

    sql_patterns = [
        (re.compile(r'(?i)(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+.*?\s*\+\s*([a-zA-Z0-9_]+)'),
         "SQL Injection Açığı (CWE-89)",
         "SQL sorgusu doğrudan string birleştirme ile oluşturulmuş. Kullanıcı girdisi manipüle edilerek yetkisiz veri sızıntısına veya silinmesine yol açabilir. Parametreli sorgu (Parameterized Query) veya ORM kullanın."),
        (re.compile(r'(?i)\$"(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+.*?\{([a-zA-Z0-9_]+)\}'),
         "SQL Injection Açığı (String Interpolation)",
         "SQL sorgusu dize içi değer yerleştirme ($) ile oluşturulmuş. Parametreli sorgu veya Dapper/EF Core gibi ORM araçlarını tercih edin.")
    ]

    for file_entry in parsed_files:
        file_path = file_entry["file"]
        lines = file_entry["lines"]

        # Track previous line for sequential pattern matching (e.g., null assign then dereference)
        prev_line_no = None
        prev_text = ""

        for line_no, text in lines:
            trimmed = text.strip()

            # Ignore comments
            if trimmed.startswith("//") or trimmed.startswith("#") or trimmed.startswith("/*"):
                continue

            # 1. Hardcoded Secret Check
            for pattern, title, desc in secret_patterns:
                match = pattern.search(trimmed)
                if match:
                    # Ignore common test dummy values if explicit
                    val = match.group(2) if len(match.groups()) >= 2 else ""
                    if not val.lower().startswith("your_") and not val == "********":
                        issues.append(Issue(
                            severity="CRITICAL",
                            category="Güvenlik Açığı",
                            file_path=file_path,
                            line_no=line_no,
                            message=f"**{title}**: {desc}",
                            code_snippet=trimmed
                        ))

            # 2. SQL Injection Check
            for pattern, title, desc in sql_patterns:
                if pattern.search(trimmed):
                    issues.append(Issue(
                        severity="CRITICAL",
                        category="Güvenlik Açığı",
                        file_path=file_path,
                        line_no=line_no,
                        message=f"**{title}**: {desc}",
                        code_snippet=trimmed
                    ))

            # 3. Guaranteed Null Reference Check (e.g., string name = null; ... name.ToUpper())
            null_assign_match = re.search(r'\b(string|var|object|[A-Z]\w*)\s+(\w+)\s*=\s*null\b', prev_text)
            if null_assign_match and prev_line_no:
                var_name = null_assign_match.group(2)
                if re.search(rf'\b{re.escape(var_name)}\.\w+', trimmed) and "if" not in trimmed and "?" not in trimmed:
                    issues.append(Issue(
                        severity="CRITICAL",
                        category="Çökme Riski",
                        file_path=file_path,
                        line_no=line_no,
                        message=f"**NullReferenceException Riski**: `{var_name}` değişkenine `{prev_line_no}`. satırda `null` atanmış ve kontrol edilmeksizin `{line_no}`. satırda çağrılmış. Bu işlem çalışma zamanında uygulamanın çökmesine yol açar.",
                        code_snippet=trimmed
                    ))

            # 4. Console.WriteLine in Controller / Service check
            if ("Controller" in file_path or "Service" in file_path) and "Console.WriteLine(" in trimmed:
                issues.append(Issue(
                    severity="WARNING",
                    category="Temiz Kod",
                    file_path=file_path,
                    line_no=line_no,
                    message="**Logging Anti-Pattern**: Controller veya servis katmanında `Console.WriteLine` kullanımı önerilmez. Yapılandırılmış bir loglama kütüphanesi (`ILogger`, Serilog vb.) kullanın.",
                    code_snippet=trimmed
                ))

            # 5. Weak Parameter Typing check
            if "Controller" in file_path and re.search(r'public\s+\w+\s+\w+\(\s*string\s+(userId|id)\s*\)', trimmed):
                issues.append(Issue(
                    severity="INFO",
                    category="Temiz Kod",
                    file_path=file_path,
                    line_no=line_no,
                    message="**Zayıf Tip Tanımı**: Kimlik (Id) parametresi `string` olarak alınmış. Sayısal veya Guid tipinde bir kimlik bekleniyorsa, tip güvenliği ve model validasyonu için doğrudan `int`, `long` veya `Guid` kullanılmalıdır.",
                    code_snippet=trimmed
                ))

            # 6. Synchronous Void Method with DB/IO in Name
            if re.search(r'public\s+void\s+(Get|Fetch|Save|Create|Delete|Update)\w*\(', trimmed):
                issues.append(Issue(
                    severity="WARNING",
                    category="Temiz Kod",
                    file_path=file_path,
                    line_no=line_no,
                    message="**Metot İmzası & Asenkronluk**: Veri tabanı veya I/O operasyonu gerçekleştiren metotlar `void` dönmemeli; veri nesnesi (`UserDto` vb.) dönmeli ve thread havuzunu kilitlememek için `async Task<...>` olarak tasarlanmalıdır.",
                    code_snippet=trimmed
                ))

            prev_line_no = line_no
            prev_text = trimmed

    return issues


def analyze_with_gemini(diff_text: str, api_key: str) -> Optional[str]:
    """Calls Google Gemini API (gemini-2.0-flash) to provide AI-assisted code review."""
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key={api_key}"

    prompt = f"""Sen deneyimli bir Kıdemli Yazılım Mühendisi ve Siber Güvenlik Uzmanısın (Staff Software Engineer / Security Auditor).
Aşağıdaki Git Diff kod değişikliklerini incele.

Kurallar:
1. Yanıtını Türkçe, net, profesyonel ve Markdown formatında ver.
2. Aşağıdaki ana bölümleri içersin:
   - 🚨 **Güvenlik Açıkları (Security Vulnerabilities)**: CWE kodları, OWASP riskleri ve saldırı senaryoları.
   - 💥 **Sistemin Çökmesine Yol Açacak Hatalar (Reliability & Crash Bugs)**: Null dereference, bellek sızıntısı, istisna yönetimi.
   - 🧹 **Temiz Kod ve Mimari İyileştirmeleri (Clean Code & Architecture)**: SOLID, logging, tip güvenliği.
   - 💡 **Önerilen Düzeltmeler (Refactored Code)**: Hataların nasıl düzeltilmesi gerektiğini gösteren temiz kod örneği.
3. Gereksiz laf kalabalığından kaçın, doğrudan satır ve dosya referanslarıyla çözüm odaklı ol.

Git Diff:
```diff
{diff_text[:12000]}
```
"""

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 2048
        }
    }

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=40) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            candidates = res_data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
    except Exception as e:
        print(f"[UYARI] Gemini API çağrısı sırasında hata oluştu: {e}", file=sys.stderr)
        return None

    return None


def generate_markdown_report(static_issues: List[Issue], ai_review: Optional[str], has_gemini_key: bool) -> str:
    """Combines static rule results and AI feedback into a rich Markdown report."""
    critical_count = sum(1 for i in static_issues if i.severity == "CRITICAL")
    warning_count = sum(1 for i in static_issues if i.severity == "WARNING")
    info_count = sum(1 for i in static_issues if i.severity == "INFO")

    lines = []
    lines.append(f"{BOT_SIGNATURE}")
    lines.append("## 🤖 Otomatik Kod İnceleme Raporu (PR Code Review Bot)\n")

    # Summary Badge Table
    status_emoji = "❌" if critical_count > 0 else ("⚠️" if warning_count > 0 else "✅")
    status_text = "Düzeltilmesi Gereken Kritik Hatalar Var!" if critical_count > 0 else ("İyileştirmeler Öneriliyor" if warning_count > 0 else "Kod İncelemeden Başarıyla Geçti")

    lines.append(f"**Durum:** {status_emoji} {status_text}\n")
    lines.append("| Metrik | Değer |")
    lines.append("|---|---|")
    lines.append(f"| 🚨 Kritik Hatalar (Güvenlik / Çökme) | **{critical_count}** |")
    lines.append(f"| ⚠️ Uyarılar (Clean Code / Anti-Pattern) | **{warning_count}** |")
    lines.append(f"| 💡 Bilgilendirme / İyileştirme | **{info_count}** |")
    lines.append(f"| 🧠 Yapay Zeka (AI) Denetimi | {'Aktif (Gemini 2.5 Flash)' if ai_review else ('Pasif (API Key Tanımlanmadı)' if not has_gemini_key else 'Başarısız/Zaman Aşımı')} |")
    lines.append("\n---\n")

    # Static findings list
    if static_issues:
        lines.append("### 🔍 Statik Kural Denetim Bulguları\n")
        for idx, issue in enumerate(static_issues, 1):
            sev_badge = "🔴 **KRİTİK**" if issue.severity == "CRITICAL" else ("🟡 **UYARI**" if issue.severity == "WARNING" else "🔵 **BİLGİ**")
            line_str = f":{issue.line_no}" if issue.line_no else ""
            lines.append(f"#### {idx}. {sev_badge} [{issue.category}] `{issue.file_path}{line_str}`")
            lines.append(f"{issue.message}\n")
            if issue.code_snippet:
                lines.append("```csharp")
                lines.append(issue.code_snippet)
                lines.append("```\n")
        lines.append("---\n")
    else:
        lines.append("### 🔍 Statik Kural Denetim Bulguları\n")
        lines.append("✅ Statik kurallara takılan herhangi bir güvenlik açığı veya kritik hata tespit edilmedi.\n\n---\n")

    # AI Review Section
    if ai_review:
        lines.append("### 🧠 Yapay Zeka Destekli Derin İnceleme (Gemini 2.5 Flash)\n")
        lines.append(ai_review.strip())
        lines.append("\n")
    else:
        lines.append("### 💡 İpucu: Yapay Zeka ile İncelemeyi Aktifleştirme\n")
        lines.append("> GitHub Repository Secrets alanına `GEMINI_API_KEY` ekleyerek yapay zeka destekli tam kod mimarisi analizini aktifleştirebilirsiniz.\n")

    lines.append("\n---\n*Bu rapor [PR Code Review Bot](https://github.com) tarafından otomatik olarak oluşturulmuştur.*")
    return "\n".join(lines)


def post_github_pr_comment(report_markdown: str):
    """Posts or updates comment on the GitHub Pull Request using GitHub REST API."""
    github_token = os.environ.get("GITHUB_TOKEN")
    event_path = os.environ.get("GITHUB_EVENT_PATH")

    if not github_token or not event_path or not os.path.exists(event_path):
        print("[BİLGİ] GITHUB_TOKEN veya GITHUB_EVENT_PATH bulunamadı, PR yorumu gönderilmedi (Yerel çalıştırma modu).")
        return

    try:
        with open(event_path, "r", encoding="utf-8") as f:
            event_data = json.load(f)

        pr_info = event_data.get("pull_request")
        if not pr_info:
            print("[BİLGİ] GitHub Event pull_request nesnesi içermiyor.")
            return

        pr_number = pr_info.get("number")
        repo_full_name = event_data.get("repository", {}).get("full_name")

        if not pr_number or not repo_full_name:
            print("[UYARI] Repository veya PR numarası tespit edilemedi.")
            return

        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "PR-Code-Review-Bot"
        }

        # 1. Fetch existing comments to see if our bot previously commented
        comments_url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
        req = urllib.request.Request(comments_url, headers=headers)
        bot_comment_id = None

        try:
            with urllib.request.urlopen(req) as resp:
                comments = json.loads(resp.read().decode("utf-8"))
                for c in comments:
                    if BOT_SIGNATURE in c.get("body", ""):
                        bot_comment_id = c.get("id")
                        break
        except Exception as e:
            print(f"[UYARI] Mevcut PR yorumları taranırken hata: {e}")

        # 2. Update existing comment or post a new one
        if bot_comment_id:
            update_url = f"https://api.github.com/repos/{repo_full_name}/issues/comments/{bot_comment_id}"
            data = json.dumps({"body": report_markdown}).encode("utf-8")
            update_req = urllib.request.Request(update_url, data=data, headers=headers, method="PATCH")
            with urllib.request.urlopen(update_req) as resp:
                print(f"[BAŞARILI] Mevcut PR yorumu ({bot_comment_id}) güncellendi.")
        else:
            create_url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
            data = json.dumps({"body": report_markdown}).encode("utf-8")
            create_req = urllib.request.Request(create_url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(create_req) as resp:
                print(f"[BAŞARILI] PR #{pr_number} üzerine yeni inceleme yorumu eklendi.")

    except Exception as e:
        print(f"[HATA] GitHub PR yorumu gönderilemedi: {e}", file=sys.stderr)


def write_to_step_summary(report_markdown: str):
    """Writes the markdown report to GitHub Step Summary if running in GitHub Actions."""
    step_summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_file:
        try:
            with open(step_summary_file, "a", encoding="utf-8") as f:
                f.write(report_markdown + "\n")
            print("[BAŞARILI] GitHub Actions Step Summary'ye rapor yazıldı.")
        except Exception as e:
            print(f"[UYARI] GITHUB_STEP_SUMMARY yazılamadı: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Automated PR Code Review Bot")
    parser.add_argument("--base", default="main", help="Base branch/commit to compare against (default: main)")
    parser.add_argument("--head", default="HEAD", help="Head branch/commit (default: HEAD)")
    parser.add_argument("--diff-file", help="Path to a pre-generated git diff file")
    parser.add_argument("--output", help="Path to save markdown report file")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit with code 1 if critical issues found")
    args = parser.parse_args()

    print(f"=== Otomatik Kod İnceleme Başlatılıyor (Base: {args.base}, Head: {args.head}) ===")

    diff_text = get_git_diff(args.base, args.head, args.diff_file)
    if not diff_text.strip():
        print("[BİLGİ] Karşılaştırılan dallar arasında herhangi bir kod değişikliği (diff) bulunamadı.")
        sys.exit(0)

    print(f"[BİLGİ] Diff boyutu: {len(diff_text)} karakter. Dosyalar ayrıştırılıyor...")
    parsed_files = parse_diff_lines(diff_text)
    print(f"[BİLGİ] Değişen dosya sayısı: {len(parsed_files)}")

    # 1. Run static rule-based analysis
    static_issues = analyze_with_static_rules(parsed_files)
    print(f"[BİLGİ] Statik kural denetimi tamamlandı. Bulunan sorun sayısı: {len(static_issues)}")

    # 2. Check for Gemini API Key and run AI analysis if available
    gemini_key = os.environ.get("GEMINI_API_KEY")
    ai_review = None
    if gemini_key:
        print("[BİLGİ] GEMINI_API_KEY tespit edildi. Gemini 2.5 Flash ile derin inceleme yapılıyor...")
        ai_review = analyze_with_gemini(diff_text, gemini_key)
    else:
        print("[BİLGİ] GEMINI_API_KEY ortam değişkeni bulunamadı. Yalnızca statik kural motoru çalıştırıldı.")

    # 3. Generate Markdown Report
    report = generate_markdown_report(static_issues, ai_review, bool(gemini_key))

    # 4. Output to terminal
    print("\n" + "=" * 50)
    print(report)
    print("=" * 50 + "\n")

    # 5. Output to file if requested
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[BAŞARILI] Rapor dosyaya kaydedildi: {args.output}")

    # 6. Write to GitHub Step Summary
    write_to_step_summary(report)

    # 7. Post comment to PR if running in GitHub Actions
    post_github_pr_comment(report)

    # 8. Check exit code
    critical_count = sum(1 for i in static_issues if i.severity == "CRITICAL")
    if args.fail_on_critical and critical_count > 0:
        print(f"[HATA] {critical_count} adet kritik güvenlik/çökme hatası tespit edildiği için inceleme başarısız oldu!")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
