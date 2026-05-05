const checks = [
  "YAML lint",
  "App check",
  "Syscheck",
  "Ansible lint",
  "Ansible syntax",
  "Helm lint",
  "Dockerfile lint",
  "Secrets scan",
  "Dependency audit",
  "Docker build",
  "Trivy scan",
  "GHCR publish",
];

const root = document.querySelector("#checks");

for (const check of checks) {
  const item = document.createElement("div");
  item.className = "check";

  const name = document.createElement("span");
  name.textContent = check;

  const status = document.createElement("span");
  status.textContent = "✅ configured";

  item.append(name, status);
  root.appendChild(item);
}
