"""
Yashigani OPA Policy Assistant (v0.7.0)
========================================
Natural language → RBAC JSON suggestion, with admin approve/reject flow.

Flow:
  1. Admin describes an access control requirement in plain English.
  2. Generator sends the description to Ollama (qwen2.5:3b) with the RBAC schema as context.
  3. Response is parsed and validated against the RBAC data document JSON schema.
  4. Admin reviews the suggestion (diff shown if a current document exists).
  5. Admin approves → gateway applies the update and writes an audit event.
  6. Admin rejects → nothing changes.

Constraints:
  - Only generates the data document (JSON). Never generates or modifies Rego files.
  - All suggestions must pass schema validation before being shown to admin.
  - Validation failures return a clear error; they never silently apply anything.
  - All generation/apply/reject actions are written to the audit log.
"""
