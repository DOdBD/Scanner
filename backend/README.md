# Domain Scanner — Backend

FastAPI backend for the domain intelligence scanner. Runs all scans server-side and writes results to Supabase.

## Prerequisites

- Python 3.11+
- A Supabase project with `schema.sql` applied (run it in the Supabase SQL editor)
- Anthropic API key
- OpenAI API key

## Setup

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

# 2. Install dependencies (from the repo root)
pip install -r requirements.txt

# 3. Copy the env example and fill in your keys
cp .env.example .env
# edit .env with your keys

# 4. Start the server
uvicorn backend.main:app --reload --port 8000
```

The API is now available at `http://localhost:8000`.

## Endpoint

### `POST /scan`

**Body**
```json
{ "domain": "clay.com", "email": null }
```
`email` is optional. When provided a lead record is upserted in Supabase.

**Returns** a full scan JSON object (see `main.py` for the shape).

## Supabase setup notes

- Enable the `vector` extension in your Supabase project before running `schema.sql`.
  In the SQL editor: `create extension if not exists vector;`
- Use the **service role key** (`SUPABASE_KEY`) so the backend can write to the database.
  Do not expose this key in the frontend.

## Environment variables

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Used for GEO synthesis (claude-sonnet-4-6) |
| `OPENAI_API_KEY` | Used for text-embedding-3-small |
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_KEY` | Supabase service role key |
