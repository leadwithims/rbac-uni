# MHP — Attribute-Based Access Control (ABAC) Policy

**Platform:** Media Hosting Platform (MHP), multi-tenant (MHP + customer orgs).  
**Relation to RBAC:** RBAC role assignments populate **subject attributes** (`subject.roles`, `subject.active_role_set`). This policy adds **resource**, **environment**, and **context** attributes so decisions can express *dept scope*, *visibility*, *ownership*, *maintenance*, and *emergency mode* in one framework.

**Decision shape:** Evaluate `Permit` / `Deny` / `NotApplicable` for a request  
`(subject, action, resource [, environment])`.  
**Algorithm (summary):** If any applicable rule yields **Deny**, the decision is **Deny** (deny-overrides). Else if any applicable rule yields **Permit**, **Permit**. Else **Deny** (default deny for unspecified cases).

---

## 1. Actions (`action.id`)

| Category | `action.id` | Notes |
|----------|-------------|--------|
| Read | `view` | Stream metadata + content |
| Social | `like`, `comment` | On media or thread |
| Share | `share` | Reshare / internal distribution per product rules |
| Publish | `upload`, `edit`, `manage_visibility`, `schedule_publication`, `delete` | On media or channel |
| Subscription | `subscribe` | To department channel |
| Account | `update_account`, `create_account`, `suspend_account` | Target user scope |
| Moderation | `report_abuse` | Creates case / ticket; no direct suspend |
| Admin | `log_review` | Read audit slice (if implemented) |

---

## 2. Subject attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `subject.user_id` | string | Stable user identifier |
| `subject.account_type` | enum | `personal` \| `employee` (HR-managed job account) |
| `subject.roles` | set | Assigned RBAC roles: `external_viewer`, `employee`, `media_editor`, `moderator`, `administrator`, `admin_emergency` |
| `subject.active_roles` | set | Roles active **in this session** (supports DSOD: e.g. moderator session drops conflicting duties) |
| `subject.org_id` | string | Tenant / company using MHP |
| `subject.department_ids` | set | Departments the subject belongs to (for *dept-scoped* internal/confidential content) |
| `subject.attributes.login_nickname` | string | Immutable display id (updates forbidden) |
| `subject.emergency_active` | boolean | **true** only if emergency admin role activated per operational SoD + time window |
| `subject.emergency_window_id` | string | Optional id of approved activation (audit) |

**Convention:** Effective permissions use **`subject.active_roles`**, not the static `subject.roles` list, when the system enforces dynamic separation of duty.

---

## 3. Resource attributes (media, channel, account)

### 3.1 Media (`resource.type = media`)

| Attribute | Type | Description |
|-----------|------|-------------|
| `resource.id` | string | Media identifier |
| `resource.visibility` | enum | `public` \| `internal` \| `confidential` |
| `resource.owner_user_id` | string | Uploader / owner |
| `resource.department_id` | string | Owning department for dept channel content |
| `resource.channel_type` | enum | `personal` \| `department` |
| `resource.org_id` | string | Owning organisation |
| `resource.state` | enum | `draft` \| `published` \| `scheduled` \| `suspended` |

### 3.2 Channel (`resource.type = channel`)

| Attribute | Type | Description |
|-----------|------|-------------|
| `resource.channel_type` | enum | `personal` \| `department` |
| `resource.owner_user_id` / `resource.department_id` | string | As appropriate |
| `resource.org_id` | string | Owning organisation |

### 3.3 Account (`resource.type = account`)

| Attribute | Type | Description |
|-----------|------|-------------|
| `resource.account_id` | string | Target account |
| `resource.account_type` | enum | `personal` \| `employee` |

---

## 4. Environment attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `environment.maintenance_mode` | boolean | **true** ⇒ all **write** actions denied globally (see §7) |
| `environment.current_time` | datetime | For emergency activation windows, schedule publication checks |
| `environment.ip_reputation` | string | Optional; future policy refinement |

---

## 5. Helper predicates (reuse in rules)

```
defined(subject.active_roles)
has_role(r) := r ∈ subject.active_roles
same_org := subject.org_id = resource.org_id
owns_media := subject.user_id = resource.owner_user_id
dept_member := resource.department_id ∈ subject.department_ids
personal_channel := resource.channel_type = personal
dept_channel := resource.channel_type = department
write_action := action.id ∈ { like, comment, share, upload, edit, manage_visibility,
                              schedule_publication, delete, subscribe,
                              update_account, create_account, suspend_account, report_abuse }
personal_account_target := resource.type = account ∧ resource.account_id = subject.user_id
employee_account_target := resource.type = account ∧ resource.account_type = employee
nickname_field := context.attribute_name = login_nickname   // implementation-specific
```

**Visibility access (read path):**

- `can_view_public := resource.visibility = public`
- `can_view_internal := resource.visibility = internal ∧ same_org ∧ dept_member`
- `can_view_confidential := resource.visibility = confidential ∧ same_org ∧ dept_member`

---

## 6. Policy rules (Permit)

Each line: **Permit** when the **condition** holds. Unless stated, require `same_org`.

### 6.1 View

| Rule ID | Condition |
|---------|-----------|
| P-VIEW-01 | `action.id = view` ∧ `can_view_public` |
| P-VIEW-02 | `action.id = view` ∧ `can_view_internal` ∧ `has_role(employee) ∨ has_role(media_editor) ∨ has_role(administrator) ∨ has_role(admin_emergency)` |
| P-VIEW-03 | `action.id = view` ∧ `can_view_confidential` ∧ `(has_role(employee) ∨ has_role(media_editor))` — *optionally tighten to editors-only per org policy* |
| P-VIEW-04 | `action.id = view` ∧ `has_role(administrator) ∨ has_role(admin_emergency)` ∧ internal/confidential in same org (full org scope for admin) |
| P-VIEW-05 | `action.id = view` ∧ `has_role(admin_emergency)` ∧ emergency scope override for incident response |

### 6.2 Like / comment

| Rule ID | Condition |
|---------|-----------|
| P-SOC-01 | `action.id ∈ {like, comment}` ∧ `can_view_public` ∧ `has_role(external_viewer)` ∧ ¬`has_role(moderator)` *or use active_roles that exclude mod social deny* |
| P-SOC-02 | Same as P-SOC-01 with `has_role(employee)` / `has_role(media_editor)` for public |
| P-SOC-03 | `action.id ∈ {like, comment}` ∧ `can_view_internal` ∧ `(has_role(employee) ∨ has_role(media_editor))` ∧ ¬`has_role(moderator)` in **effective** conflict checks |
| P-SOC-04 | Administrator: optional permit on public/internal per org least-privilege choice |

**Moderator DSOD:** If `has_role(moderator)` in `active_roles` and static/dynamic SoD applies, **exclude** `like` and `comment` even when `employee` would allow (implement via §8 composite constraint).

### 6.3 Share / upload (personal vs department)

| Rule ID | Condition |
|---------|-----------|
| P-SHR-01 | `action.id = share` ∧ `resource.visibility = internal` ∧ `can_view_internal` ∧ `(has_role(employee) ∨ has_role(media_editor))` ∧ ¬`has_role(moderator)` |
| P-UPL-01 | `action.id = upload` ∧ `personal_channel` ∧ `owns_media ∨ personal_account_target` ∧ `(has_role(employee) ∨ has_role(media_editor))` ∧ ¬`has_role(moderator)` |
| P-UPL-02 | `action.id = upload` ∧ `dept_channel` ∧ `dept_member` ∧ `has_role(media_editor)` |

### 6.4 Edit / visibility / schedule

| Rule ID | Condition |
|---------|-----------|
| P-MNT-01 | `action.id ∈ {edit, manage_visibility, schedule_publication}` ∧ `dept_channel` ∧ `dept_member` ∧ `has_role(media_editor)` |

### 6.5 Subscribe

| Rule ID | Condition |
|---------|-----------|
| P-SUB-01 | `action.id = subscribe` ∧ `dept_channel` ∧ `(has_role(employee) ∨ has_role(media_editor))` ∧ ¬`has_role(moderator)` |

### 6.6 Report abuse

| Rule ID | Condition |
|---------|-----------|
| P-RPT-01 | `action.id = report_abuse` ∧ `has_role(moderator)` ∧ (`can_view_public` ∨ `can_view_internal` ∨ `can_view_confidential`) |

### 6.7 Account management

| Rule ID | Condition |
|---------|-----------|
| P-ACC-01 | `action.id = update_account` ∧ `personal_account_target` ∧ `resource.account_type = personal` ∧ `(has_role(external_viewer) ∨ has_role(employee) ∨ has_role(media_editor))` ∧ **not** updating nickname (§7) |
| P-ACC-02 | `action.id ∈ {create_account, update_account, suspend_account}` ∧ `employee_account_target` ∧ `has_role(administrator)` |
| P-ACC-03 | `action.id = update_account` ∧ `personal_account_target` ∧ `has_role(administrator)` *(admin assists user; optional)* |

### 6.8 Emergency administrator

| Rule ID | Effect |
|---------|--------|
| P-EMG-01 | **Permit** when `has_role(admin_emergency)` ∧ `subject.emergency_active = true` — all actions needed for incident handling within org policy, fully audited. Prefer enumerating actions in production; coursework may document this as a single override rule. |

---

## 7. Policy rules (Deny) — overrides Permit

| Rule ID | Condition |
|---------|-----------|
| D-MNT-01 | `environment.maintenance_mode = true` ∧ `write_action` | **Deny** |
| D-NICK-01 | `action.id = update_account` ∧ `nickname_field` targeted | **Deny** (all roles) |
| D-SOD-01 | `has_role(moderator)` in `active_roles` ∧ `action.id ∈ {like, comment, share, upload, edit, manage_visibility, schedule_publication, delete, subscribe}` | **Deny** (moderator as pure oversight role in conflict-free session) |
| D-CONF-01 | `resource.visibility = confidential` ∧ `¬dept_member` ∧ `action.id = view` | **Deny** unless admin rule applies |

---

## 8. Combining RBAC and ABAC (implementation note)

1. **Provisioning:** HR / admin tools assign RBAC roles → stored as `subject.roles`.  
2. **Session start:** Compute `subject.active_roles` from chosen profile (e.g. “work as moderator” ⇒ drop incompatible content-creation bits per D-SOD-01).  
3. **Evaluation:** PDP loads attributes, evaluates §6 then §7.  
4. **Emergency:** Grant `admin_emergency` only with `subject.emergency_active` and time-bounded approval (operational SoD, ≥2 admins).

---

## 9. Traceability to RBAC diagram

| RBAC artefact | ABAC expression |
|---------------|------------------|
| Role hierarchy | `subject.roles` / `active_roles` |
| “Dept only” internal/confidential | `dept_member`, `same_org` |
| Moderator = report abuse | `P-RPT-01`; social/content denies via `D-SOD-01` |
| Admin account ops | `P-ACC-02` |
| Emergency full access | `P-EMG-01` + `subject.emergency_active` |
| DENY nickname / maintenance | `D-NICK-01`, `D-MNT-01` |

---

## 10. Open items (for your report)

- **Confidential `view`:** tighten P-VIEW-03 to editors-only or add org-specific attribute `resource.clearance_level`.  
- **Administrator social actions:** align P-SOC-04 with your least-privilege narrative (often **omit** like/comment for admin).  
- **XACML / Rego:** This spec maps cleanly to ALFA/XACML `Rule`/`Policy` or OPA `allow` clauses if you need machine-readable form later.
