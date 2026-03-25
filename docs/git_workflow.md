# Git Workflow — IntelliGuard Team

## Branch per Person
```
main                 ← stable, only merge after review
├── mohit/network    ← Mohit works here
├── ilma/features    ← Ilma works here
├── megha/firewall   ← Megha works here
├── priya/dashboard  ← Priya works here
└── kunal/ai         ← Kunal works here
```

## Daily Workflow
```bash
git pull origin main          # sync latest
git checkout <your-branch>    # go to your branch
# ...do your work...
git add .
git commit -m "feat: describe what you did"
git push origin <your-branch>
# create PR → review → merge to main
```

## Rules
1. NEVER commit directly to `main`
2. Only edit files inside your own module folder
3. Shared files (`config.yaml`, `requirements.txt`) → discuss first, one person commits
4. `data/logs/` and `ai_engine/models/` are git-ignored — do not force push them
