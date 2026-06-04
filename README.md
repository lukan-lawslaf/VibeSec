# VibeSec 🔐

> AI-powered security scanner for code, GitHub repositories, and live URLs.

VibeSec combines static AST analysis, RAG-augmented vulnerability detection, and real HTTP probing with AI triage — giving developers prioritised, actionable security findings instead of noisy raw dumps.

---

## Features

| Scan Mode | What It Does |
|-----------|-------------|
| **Code Scan** | AST parsing → RAG context → DeepHat V1 vulnerability detection → DeepSeek patch generation |
| **GitHub Repo Scan** | Clones any public repo, scans all Python files, aggregates findings |
| **Live URL Scan** | Real HTTP probe (headers, cookies, CORS, exposed paths) + nmap (when permitted) → Groq AI triage |

---

## Tech Stack

**Backend** — FastAPI · Python 3.11+ · ChromaDB (RAG) · HuggingFace InferenceClient · Groq  
**Frontend** — React + Vite · TypeScript · TailwindCSS · Supabase Auth  
**Models** — DeepHat V1 (vuln detection) · DeepSeek-V3 (patch generation) · Llama-3.3-70B via Groq (live triage)

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- [HuggingFace API key](https://huggingface.co/settings/tokens)
- [Groq API key](https://console.groq.com/)
- [Supabase project](https://supabase.com/) (for auth)

### 1. Clone & configure

```bash
git clone https://github.com/lukan-lawslaf/VibeSec.git
cd VibeSec
cp .env.example .env          # fill in your keys
```

`.env` keys:
```
HF_API_KEY=hf_...
GROQ_API_KEY=gsk_...
```

`frontend/.env` keys:
```
VITE_SUPABASE_URL=https://xxxx.supabase.co
VITE_SUPABASE_ANON_KEY=eyJ...
```

### 2. Backend

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API docs available at `http://localhost:8000/docs`

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend at `http://localhost:5173`

---

## API Endpoints

```
POST /api/v1/scan/static       # Scan Python source code
POST /api/v1/scan/live         # Scan a live URL
POST /api/v1/repo/scan         # Scan a GitHub repository
GET  /api/v1/scan/health       # Health check
```

---

## Project Structure

```
vibesec/
├── app/
│   ├── agents/
│   │   ├── vuln_agent.py      # DeepHat V1 vulnerability detection
│   │   ├── patch_agent.py     # DeepSeek patch generation
│   │   ├── live_agent.py      # HTTP probe + Groq triage
│   │   └── repo_agent.py      # GitHub repo scanner
│   ├── parsers/
│   │   └── ast_parser.py      # Python AST analysis
│   ├── routers/
│   │   ├── scan.py            # /scan endpoints
│   │   └── repo.py            # /repo endpoints
│   ├── utils/
│   │   └── rag.py             # ChromaDB RAG pipeline
│   └── main.py
├── frontend/                  # React + Vite app
├── .env.example
└── requirements.txt
```

---

## Notes

- **Live URL scan**: nmap is attempted via WSL but gracefully skipped if blocked. When nmap is blocked/filtered, only HTTP-layer findings (headers, cookies, CORS, exposed paths) are reported — no hallucinated network vulnerabilities.
- **Patch agent**: Changes are minimal and surgical. Import statements and third-party API names are always preserved exactly.
- **Code scan**: DeepHat V1 is instructed to ignore comments, env-var reads, and framework boilerplate (FastAPI, Supabase, HuggingFace idioms).

---

## License

MIT
