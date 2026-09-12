# Browser-Based AI Governance Layer

> **Privacy-First, On-Device Guardrails for Enterprise AI Chat Tools**  
> *Final-Year Computer Engineering Project & Research Paper Prototype*

---

## 📌 Executive Overview

As enterprise employees increasingly rely on AI chat tools like **ChatGPT**, **Google Gemini**, and **Anthropic Claude**, organizations face major data leakage risks — including accidental exposure of personally identifiable information (PII), protected health information (PHI), financial ledgers, secret API keys, and corporate secrets.

This project implements a **privacy-first, plug-and-play Chrome Extension (Manifest V3)** that intercepts user prompts pre-flight before network submission. It combines zero-dependency regex pattern matching with **Chrome's built-in on-device Gemini Nano AI (`LanguageModel` Prompt API)** to compute normalized risk scores, enforce a two-layer security policy, and provide transparent human-readable explainability.

**Key Guarantee:** All prompt content analysis and audit logging occur **100% locally on the user's browser device**. No raw prompt text is ever transmitted over network sockets to any external server.

---

## 🏛️ System Architecture & Workflow

```
[ User Action: Enter / Submit Click in AI Chat ]
                      │
                      ▼
        [ Content Script Intercepts Pre-Flight ]
                      │
                      ▼
     ┌─────────────────────────────────────────┐
     │   Background Service Worker Engine      │
     │                                         │
     │ 1. Structured Regex Detector            │
     │    (Luhn CC, API Keys, SSN, Emails)     │
     │                                         │
     │ 2. Contextual On-Device Gemini Nano     │
     │    (Chrome Prompt API LanguageModel)    │
     │                                         │
     │ 3. Risk Scoring & Role Multipliers      │
     │                                         │
     │ 4. Two-Layer Policy Engine              │
     │    • Fixed Security Floor (Immutable)   │
     │    • Admin Customizable Layer           │
     └─────────────────────────────────────────┘
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
   [ BLOCK ]      [ REDACT ]      [ ALLOW ]
   Modal Alert   Auto-Clean &     Submission
                 Resend Button     Proceeds
```

---

## 🛠️ Tech Stack & Module Directory

- **Manifest V3 Extension**: Vanilla JavaScript (ES6+), HTML5, CSS3.
- **Interception Script**: `content.js` & `content.css` targeting `chatgpt.com`, `chat.openai.com`, `gemini.google.com`, and `claude.ai`.
- **Structured Pattern Detector**: `detectors/regex.js` with Luhn algorithm validation.
- **Contextual On-Device AI**: `detectors/llm.js` utilizing Chrome's `LanguageModel` Prompt API.
- **Risk Scoring Engine**: `engine/risk-score.js` (Normalized 0–100 score incorporating role weights and domain trust multipliers).
- **Two-Layer Policy Engine**: `engine/policy.js` (Fixed Security Floor + Admin Customizable threshold layer).
- **Explanation Generator**: `engine/explain.js` (Transparent user next-step advice).
- **Audit Storage**: `storage/audit.js` (Local browser IndexedDB `AIGovernanceDB`).
- **Admin Popup UI**: `popup/popup.html`, `popup.css`, `popup.js` (Dark glassmorphism design).
- **Evaluation Suite**: `eval/eval-runner.html`, `eval/eval-runner.js`, `eval/score.js`, `eval/test-set.json`.

---

## 🚀 Installation & Developer Setup

1. **Clone or Download Workspace Repository**:
   Ensure all files are located in your target workspace directory.

2. **Enable Chrome On-Device AI (Gemini Nano)**:
   - Ensure you are running **Google Chrome Version 127+**.
   - Navigate to `chrome://flags` in Chrome.
   - Enable `#optimization-guide-on-device-model` (Set to *Enabled BypassPerfRequirement*).
   - Enable `#prompt-api-for-gemini-nano` (Set to *Enabled*).
   - Relaunch Chrome.

3. **Load Extension in Developer Mode**:
   - Open `chrome://extensions/` in Chrome.
   - Toggle **Developer mode** (top-right switch) to `ON`.
   - Click **Load unpacked**.
   - Select the project root folder.

---

## 🧪 Testing & Research Evaluation Suite

### 1. Run Automated Unit Tests
To verify regex rules, Luhn algorithm accuracy, and fixed security floor immutability:
```bash
node test/run-tests.js
```

### 2. Run Standalone Regex Metrics Benchmark
To calculate Precision, Recall, F1, and Accuracy for structured regex checks:
```bash
node eval/score.js
```

### 3. Run In-Browser Ablation Benchmarking (Pass 1 vs Pass 2)
To benchmark **Regex-Only** vs **Hybrid Regex + On-Device Gemini Nano**:
1. Click the AI Governance extension icon in Chrome to open the Admin Popup.
2. Navigate to the **Eval Suite** tab and click **Launch Evaluation Runner Page** (or navigate to `chrome-extension://<EXTENSION_ID>/eval/eval-runner.html`).
3. Click **Run Pass 1: Regex Only** and **Run Pass 2: Hybrid (Regex + On-Device Gemini Nano)**.
4. Save the downloaded result files (`results-regex-only.json` and `results-regex-llm.json`) into the `eval/` folder.
5. Re-run `node eval/score.js` in your terminal to view the complete side-by-side comparative ablation table and average/median LLM latency stats.

---

## 🔬 Research & Ethics Disclosure & Scope Limitations

- **Synthetic Dataset**: All 50 prompts in `eval/test-set.json` are 100% synthetic, generated solely for academic evaluation. No real personal identities, actual credit cards, live API credentials, or real medical records were used.
- **Fail-Closed Image & Unscannable File Guardrail (Documented Limitation)**: Plain image files (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`), encrypted PDFs, and unrecognized binary formats cannot be text-extracted without heavy OCR worker models. To prevent heavy OCR resource overhead and guarantee zero data leaks, the system enforces a **Fail-Closed Security Guardrail**: unscannable attachments trigger an immediate security policy alert (`BLOCK` or `WARN` with a clear explanation) rather than silently allowing unverified files.
- **Scope Limitations**: Prototype evaluation targets major web AI chat clients (ChatGPT, Gemini, Claude). File text extraction supports `.txt`, `.csv`, `.json`, `.md`, `.pdf`, `.docx`, and `.xlsx` fully offline. On-device LLM latency depends on local hardware capabilities.
