🤖 PR Code Review Bot

An automated, LLM-powered GitHub Action and API service that inspects incoming Pull Requests, detects security flaws and anti-patterns, and leaves concise, contextual review comments directly on your GitHub diffs.

🎯 Overview

Manual code reviews are vital for maintaining code quality, yet engineering hours are frequently drained by surface-level syntax issues, recurring anti-patterns, and overlooked credential leaks.

PR Code Review Bot bridges GitHub PR workflows with modern Large Language Model (LLM) APIs (such as Google Gemini or OpenAI). Triggered on every pull request event, it automatically evaluates the patch diff, checks for best practices, and returns an actionable review summary before human reviewers step in.

✨ Key Features

Automated Diff Inspection: Listens to pull_request events to extract code diffs without requiring local checkouts.

LLM-Driven Code Analysis: Pinpoints logic errors, unhandled boundary cases, performance bottlenecks, and architectural anti-patterns.

Security & Secret Auditing: Proactively flags exposed API keys, connection strings, SQL injection risks, and missing input sanitization.

Inline & Summary Feedback: Posts structured, Markdown-formatted review summaries and actionable inline comments directly to the GitHub PR thread.

Token Budgeting & Diff Truncation: Sanitizes and splits large patches to prevent API rate-limit overruns and optimize token consumption.

🏗️ Architecture & Review Flow

[ Developer Opens / Updates Pull Request ]
                    │
                    ▼
          [ GitHub Actions Runner ]
                    │
                    ▼
       [ PR Code Review Bot Engine ]
         ├── 1. Fetches PR patch diff via GitHub API (Octokit)
         ├── 2. Sanitizes input & trims non-code noise
         ├── 3. Constructs structured prompt for LLM (Gemini API)
         └── 4. Parses structured JSON response & issues
                    │
                    ▼
[ Posts Inline Comments & Review Summary to GitHub PR ]


🛠️ Tech Stack & Dependencies

Runtime / Language: Node.js (v20+) / TypeScript

GitHub API Client: @actions/core, @actions/github, @octokit/rest

AI / LLM Integration: Google Gemini API (@google/genai) or OpenAI API

CI/CD Platform: GitHub Actions Workflows

🚀 Getting Started & Local Setup

Prerequisites

Node.js 20+

Git

A Google Gemini API Key (or OpenAI API Key)

A GitHub Personal Access Token (PAT) with repo scope (for local testing)

Step 1: Clone the Repository

git clone https://github.com/dururencber/pr-code-review-bot.git
cd pr-code-review-bot


Step 2: Install Dependencies

npm install


Step 3: Configure Environment Variables

Create a .env file in the project root (ensure this file is listed in .gitignore):

# AI Service Credentials
AI_API_KEY=your_gemini_api_key_here

# GitHub Token for API Calls
GITHUB_TOKEN=your_personal_access_token_here


Step 4: Build and Run Locally

# Compile TypeScript to JavaScript
npm run build

# Run local execution test
npm start


⚙️ GitHub Actions Integration

To deploy this bot on any of your repositories, create a workflow file at .github/workflows/ai-code-review.yml:

name: "AI PR Code Review"

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run PR Code Review Bot
        uses: dururencber/pr-code-review-bot@main
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          AI_API_KEY: ${{ secrets.AI_API_KEY }}


🔒 Security & Best Practices

Zero Credential Storage: No API keys or tokens are stored in source code. Credentials are exclusively passed via repository GitHub Secrets.

Safe Prompt Construction: Diffs are sanitized and structured to prevent prompt injection attempts hidden in commit messages or code comments.

Least Privilege Principle: The action only requests pull-requests: write permissions, minimizing security exposure across build runners.

📄 License

This project is distributed under the MIT License. See LICENSE for details.
