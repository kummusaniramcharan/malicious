import os
import json
import sqlite3
from datetime import datetime
from github import Github, Auth
from anthropic import Anthropic

# ====================== CONFIG ======================
GITHUB_APP_ID = int(os.getenv("GITHUB_APP_ID", 0))
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# ====================== DATABASE ======================
def init_db():
    conn = sqlite3.connect('opendetector.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY, github_url TEXT UNIQUE, repo_name TEXT, last_checked TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS malicious_prs (
        id INTEGER PRIMARY KEY, project_id INTEGER, pr_number INTEGER, title TEXT,
        is_malicious INTEGER DEFAULT 0, score INTEGER, detected_at TEXT,
        explanation TEXT, FOREIGN KEY(project_id) REFERENCES projects(id))''')
    conn.commit()
    conn.close()

# ====================== GITHUB APP AUTH ======================
def get_github_client():
    auth = Auth.AppAuth(app_id=GITHUB_APP_ID, private_key=GITHUB_PRIVATE_KEY)
    return Github(auth=auth)

# ====================== LLM (Claude 3.5 Sonnet) ======================
def analyze_with_llm(title, body, diff_summary=""):
    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    prompt = f"""
    You are an expert open-source security auditor.
    PR Title: {title}
    Body: {body[:400]}
    Is this PR malicious? Score 0-100. Give a clear reason in 1-2 sentences.
    """
    try:
        message = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=300,
            temperature=0,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    except:
        return "⚠️ LLM failed"

# ====================== MALICIOUS PATTERNS ======================
MALICIOUS_PATTERNS = ['malicious', 'backdoor', 'ransomware', 'crypto miner', 'phishing', 'exploit', 'malware']

def is_malicious_pr(title, body):
    title_lower = (title or "").lower()
    body_lower = (body or "").lower()
    return 1 if any(p in title_lower or p in body_lower for p in MALICIOUS_PATTERNS) else 0

# ====================== MAIN SCAN ======================
def scan_all_repos():
    init_db()
    gh = get_github_client()
    conn = sqlite3.connect('opendetector.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT github_url FROM projects")
    tracked = [row[0] for row in cursor.fetchall()]
    
    for repo_url in tracked:
        try:
            repo = gh.get_repo(repo_url)
            issues = repo.get_issues(state='open')
            
            for issue in issues:
                is_mal = is_malicious_pr(issue.title, issue.body)
                score = 95 if is_mal else 30
                explanation = analyze_with_llm(issue.title, issue.body) if is_mal else ""
                
                cursor.execute('''INSERT OR REPLACE INTO malicious_prs 
                    (project_id, pr_number, title, is_malicious, score, detected_at, explanation)
                    VALUES ((SELECT id FROM projects WHERE github_url=?), ?, ?, ?, ?, ?, ?)''',
                    (repo_url, issue.number, issue.title, is_mal, score, datetime.now().isoformat(), explanation)
                )
            
            cursor.execute("UPDATE projects SET last_checked=? WHERE github_url=?", 
                          (datetime.now().isoformat(), repo_url))
            conn.commit()
            print(f"✅ Scanned {repo_url} — {len([i for i in repo.get_issues() if i.state=='open'])} PRs")
        except Exception as e:
            print(f"⚠️ Failed {repo_url}: {e}")
    
    conn.close()

# ====================== DASHBOARD ======================
def get_dashboard_html():
    conn = sqlite3.connect('opendetector.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT repo_name, last_checked FROM projects")
    repos = cursor.fetchall()
    
    cursor.execute("""SELECT pr_number, title, is_malicious, score, detected_at, explanation 
                      FROM malicious_prs ORDER BY detected_at DESC LIMIT 30""")
    prs = cursor.fetchall()
    
    conn.close()
    
    html = f"""
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><title>OpenGuard</title>
    <style>body{{font-family:Arial;padding:20px;background:#0f0f0f;color:white;}} h1{{color:#00ff9d;}}</style></head><body>
    <h1>🔒 OpenGuard — Malicious PR Detector</h1>
    <p><strong>GitHub App</strong> • Runs every 15 minutes • Powered by Claude</p>
    
    <h2>Tracked Repos ({len(repos)})</h2>
    <table><tr><th>Repository</th><th>Last Scanned</th></tr>
    {''.join([f'<tr><td>{r[0]}</td><td>{r[1]}</td></tr>' for r in repos])}
    </table>
    
    <h2>Recent Malicious PRs ({len(prs)})</h2>
    <table>
        <tr><th>PR #</th><th>Title</th><th>Status</th><th>Score</th><th>Time</th><th>Explanation</th></tr>
        {''.join([f'<tr><td>{p[0]}</td><td>{p[1]}</td><td>{"MALICIOUS" if p[2] else "Clean"}</td><td>{p[3]}</td><td>{p[4]}</td><td>{p[5][:200]}</td></tr>' for p in prs])}
    </table>
    </body></html>
    """
    return html

# ====================== RUN ======================
if __name__ == "__main__":
    print("🚀 OpenGuard is scanning...")
    scan_all_repos()
    html = get_dashboard_html()
    with open('index.html', 'w') as f:
        f.write(html)
    print("📁 index.html updated — open it in browser!")
