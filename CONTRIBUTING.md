# Contributing to AegisML

Thank you for helping make AI more secure! 🛡️

## Ways to Contribute

- 🐛 **Bug Reports**: Open an issue with reproduction steps
- ✨ **New Features**: Discuss in issues first, then submit PR
- 🔍 **New Threat Patterns**: Add to `aegisml/scanner.py`
- 🌍 **Translations**: Improve Arabic/English content
- 📖 **Documentation**: Fix typos, improve clarity

## Development Setup

```bash
git clone https://github.com/hasanalaaa/aegisml
cd aegisml

# Backend
cd services/scan-engine
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8000

# Frontend (new terminal)
cd apps/web
pnpm install
pnpm dev
```

## Adding Threat Patterns

Edit `aegisml/scanner.py` → `THREAT_PATTERNS` list:

```python
("your_pattern", "severity", "category", "English description"),
```

## Code Standards

- Python: PEP 8, type hints, `from __future__ import annotations`
- TypeScript: no `any` types, proper interfaces
- Commits: conventional commits (`feat:`, `fix:`, `docs:`, `chore:`)

## Pull Request Process

1. Fork the repository
2. Create feature branch: `git checkout -b feat/your-feature`
3. Make changes + run `pnpm build` to verify no errors
4. Submit PR with clear description
