const fs = require("fs");
const path = require("path");

const MANAGED_START = "<!-- auto-pr:managed:start -->";
const MANAGED_END = "<!-- auto-pr:managed:end -->";

function loadTemplate(templatePath) {
  if (!fs.existsSync(templatePath)) {
    throw new Error(`Auto-PR template not found: ${templatePath}`);
  }
  return fs.readFileSync(templatePath, "utf8").trim();
}

function replacePlaceholders(text, context) {
  return text.replace(/\{\{([A-Z0-9_]+)\}\}/g, (_match, token) => {
    if (!(token in context)) {
      throw new Error(`Missing placeholder value for {{${token}}}`);
    }
    const value = context[token];
    if (value === undefined || value === null || value === "") {
      throw new Error(`Empty placeholder value for {{${token}}}`);
    }
    return String(value);
  });
}

function buildAutoPrBody({
  repoRoot,
  flowTemplateName,
  context,
  includeManualTemplate = false,
}) {
  const templatesRoot = path.join(repoRoot, ".github", "pr_templates", "auto");
  const flowTemplatePath = path.join(templatesRoot, flowTemplateName);
  const commonTemplatePath = path.join(templatesRoot, "common.md");
  const manualTemplatePath = path.join(
    repoRoot,
    ".github",
    "pull_request_template.md"
  );

  const flowTemplate = loadTemplate(flowTemplatePath);
  const commonTemplate = loadTemplate(commonTemplatePath);

  let manualTemplate = "";
  if (includeManualTemplate) {
    manualTemplate = loadTemplate(manualTemplatePath);
  }

  const merged = [flowTemplate, commonTemplate, manualTemplate]
    .filter(Boolean)
    .join("\n\n");

  const resolved = replacePlaceholders(merged, context);
  return `${MANAGED_START}\n${resolved}\n${MANAGED_END}`;
}

module.exports = {
  MANAGED_START,
  MANAGED_END,
  buildAutoPrBody,
};
