#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$HOME/projects/AoE2DEWarWagers}"
REPOS=("app-prodn" "api-prodn" "aoe2-watcher")
BRANCH="${BRANCH:-main}"

push_repo() {
  local repo="$1"
  local repo_dir="$ROOT_DIR/$repo"

  if [[ ! -d "$repo_dir/.git" ]]; then
    echo "↷ Skipping $repo (not a git repo at $repo_dir)"
    return
  fi

  cd "$repo_dir"
  local remote
  remote="$(git remote | head -n1 || true)"
  if [[ -z "$remote" ]]; then
    echo "↷ Skipping $repo (no git remote configured)"
    return
  fi

  if [[ -n "$(git status --porcelain)" ]]; then
    echo "✖ $repo has uncommitted changes. Commit or stash first."
    exit 1
  fi

  echo "↑ Pushing $repo ($remote/$BRANCH)"
  git push "$remote" "$BRANCH"
}

for repo in "${REPOS[@]}"; do
  push_repo "$repo"
done

if [[ -n "${VPS_HOST:-}" ]]; then
  VPS_PATH="${VPS_PATH:-/mnt/HC_Volume_105319120/www-moved/AoE2DEWarWagers}"
  echo "⇣ Pulling latest on VPS: $VPS_HOST ($VPS_PATH)"
  ssh "$VPS_HOST" "\
    set -euo pipefail; \
    cd '$VPS_PATH/app-prodn' && git pull --ff-only origin '$BRANCH'; \
    cd '$VPS_PATH/api-prodn' && git pull --ff-only origin '$BRANCH'"
  echo "✔ VPS repos updated."
  echo "ℹ Watcher source is MBP-local now; VPS serves built watcher artifacts from public/downloads."
  echo "ℹ If you built a new watcher release, run watcher:sync locally and then deploy/copy the downloads output."
else
  cat <<EOF
No VPS host configured. To pull on your VPS manually:
  cd /mnt/HC_Volume_105319120/www-moved/AoE2DEWarWagers/app-prodn && git pull --ff-only origin $BRANCH
  cd /mnt/HC_Volume_105319120/www-moved/AoE2DEWarWagers/api-prodn && git pull --ff-only origin $BRANCH

Watcher source stays local on MBP.
VPS should only host the built watcher artifacts in app-prodn/public/downloads.
EOF
fi