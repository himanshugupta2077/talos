# Talos: commit and push to `main` when done

When work in this Talos repository is finished (feature, fix, test, or docs):

1. Use this checkout of `himanshugupta2077/talos` (or the active worktree that tracks `origin/main`).
2. Commit on **`main` only**. Do not create a feature branch, PR branch, or stack branch unless the user names a different branch in that turn.
3. **Push to `origin/main` automatically** after a successful commit. Do not stop at “ready to commit” or “want me to push?”.
4. Never push Talos product work to any other remote branch (`client-*`, `vdi-*`, `talos-v2`, etc.).

Scope: this repo only (`talos/`, `talos-control-panel/`, `talos-docs/`, tests). Other projects in the parent workspace are unaffected.