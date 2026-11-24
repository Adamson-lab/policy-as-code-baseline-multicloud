# Run from the repo root in PowerShell after creating an empty repo on github.com/new
git init -b main
git config user.name "Favour Adamson"
git config user.email "favouradamson803@gmail.com"
git add .
git commit -m "feat: policy-as-code baseline v1.0.0"
git remote add origin https://github.com/Adamson-lab/policy-as-code-baseline-multicloud.git
git push -u origin main
