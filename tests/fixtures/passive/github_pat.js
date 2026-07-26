// Synthetic fixture — NOT a live credential
const GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
fetch("https://api.github.com/user", {
  headers: { Authorization: `token ${GITHUB_TOKEN}` },
});
