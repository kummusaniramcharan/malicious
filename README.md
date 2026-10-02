# OpenGuard — Malicious PR/Dependency Detector for Open Source

A live GitHub App that automatically scans open-source repositories for malicious PRs and suspicious dependency updates.

**Features:**
- Scans open PRs every 15 minutes
- Detects malicious keywords + LLM explanation
- Beautiful real-time dashboard
- Runs 100% on GitHub

**Setup:**
1. Create GitHub App (Settings → Apps)
2. Add `GITHUB_APP_ID` and `GITHUB_PRIVATE_KEY` as repository secrets
3. Add `ANTHROPIC_API_KEY` as repository secret
4. Deploy the workflow above

Demo: https://your-repo-name.vercel.app or your GitHub Pages
