# MHP RBAC Policy Tree

University homework — Role-Based Access Control (RBAC) policy design for a media-hosting platform (MHP).

## Overview

This project models the access-control policy of an internal media platform using a hierarchical RBAC approach. Roles inherit permissions from their parent, with explicit DENY rules that apply across all roles.

## Role Hierarchy

| Role | Inherits from | Description |
|---|---|---|
| Anonymous | — | Unauthenticated visitor |
| External Viewer | Anonymous | Registered external user |
| Employee | External Viewer | Internal staff member |
| Media Editor | Employee | Manages departmental media |
| Moderator | Employee | Monitors and enforces policy |
| Administrator | Employee (separate branch) | User and platform management |
| Emergency Admin | Administrator | Full platform override |

## Diagram

```mermaid
graph TD

  %% ── ROLE HIERARCHY ──────────────────────────────────────
  ANON["👤 Anonymous user"]:::roleAnon
  EXT["👥 External viewer"]:::roleExt
  EMP["🏢 Employee"]:::roleEmp
  EDITOR["✏️  Media editor"]:::roleSpec
  MOD["🛡️  Moderator"]:::roleSpec
  ADMIN["⚙️  Administrator"]:::roleAdmin
  EMERG["🚨 Admin · Emergency"]:::roleEmerg

  %% ── HIERARCHY LINKS ──────────────────────────────────────
  ANON -->|"registers"| EXT
  EXT  -->|"is employee"| EMP
  EMP  -->|"specialised"| EDITOR
  EMP  -->|"specialised"| MOD
  EMP  -.->|"separate branch"| ADMIN
  ADMIN -->|"emergency mode"| EMERG

  %% ── ANONYMOUS PERMISSIONS ────────────────────────────────
  subgraph SG_ANON["Anonymous permissions"]
    direction LR
    P_VIEW_PUB["view · public media"]:::permView
  end
  ANON --> SG_ANON

  %% ── EXTERNAL VIEWER PERMISSIONS ──────────────────────────
  subgraph SG_EXT["External viewer permissions  (+ inherits Anonymous)"]
    direction LR
    P_LIKE_PUB["like · public media"]:::permInteract
    P_CMT_PUB["comment · public media"]:::permInteract
    P_UPD_OWN["update · own account info"]:::permAccount
    P_LOGIN["login · platform"]:::permAuth
    P_LOGOUT["logout · platform"]:::permAuth
  end
  EXT --> SG_EXT

  %% ── EMPLOYEE PERMISSIONS ─────────────────────────────────
  subgraph SG_EMP["Employee permissions  (+ inherits Ext. Viewer)"]
    direction LR
    P_VIEW_INT["view · internal media"]:::permView
    P_LIKE_INT["like · internal media"]:::permInteract
    P_CMT_INT["comment · internal media"]:::permInteract
    P_UPLOAD_P["upload · personal channel"]:::permContent
    P_SHARE["share · internal media"]:::permContent
    P_SUB["subscribe · dept channel"]:::permInteract
  end
  EMP --> SG_EMP

  %% ── EDITOR PERMISSIONS ───────────────────────────────────
  subgraph SG_EDITOR["Media editor permissions  (+ inherits Employee)"]
    direction LR
    P_UPLOAD_D["upload · dept channel"]:::permContent
    P_EDIT["edit · dept media"]:::permContent
    P_VIS["manage visibility"]:::permContent
    P_SCHED["schedule publication"]:::permContent
    P_DELETE["delete · dept media"]:::permContent
  end
  EDITOR --> SG_EDITOR

  %% ── MODERATOR PERMISSIONS ────────────────────────────────
  subgraph SG_MOD["Moderator permissions  (+ inherits Employee)"]
    direction LR
    P_MON_V["monitor · videos"]:::permMod
    P_MON_C["monitor · comments"]:::permMod
    P_SUSP_M["suspend · media"]:::permMod
  end
  MOD --> SG_MOD

  %% ── ADMIN PERMISSIONS ────────────────────────────────────
  subgraph SG_ADMIN["Administrator permissions"]
    direction LR
    P_CREATE_A["create · user account"]:::permAdmin
    P_UPD_A["update · user account"]:::permAdmin
    P_SUSP_A["suspend · user account"]:::permAdmin
    P_LOG["log · admin/mod actions"]:::permAuth
  end
  ADMIN --> SG_ADMIN

  %% ── EMERGENCY PERMISSIONS ────────────────────────────────
  subgraph SG_EMERG["Emergency admin permissions  (full access)"]
    direction LR
    P_VIEW_ALL["view · ALL media"]:::permEmerg
    P_SUSP_ANY["suspend · any account or media"]:::permEmerg
    P_FULL["full platform access"]:::permEmerg
  end
  EMERG --> SG_EMERG

  %% ── CROSS-CUTTING DENIES ─────────────────────────────────
  subgraph SG_DENY["Explicit DENY  (all roles)"]
    direction LR
    D_NICK["✗ update · login nickname"]:::permDeny
    D_MAINT["✗ write ops during maintenance"]:::permDeny
  end

  classDef roleAnon  fill:#3d3d3a,stroke:#888780,color:#e8e8e2,rx:8
  classDef roleExt   fill:#0c447c,stroke:#185FA5,color:#B5D4F4,rx:8
  classDef roleEmp   fill:#27500a,stroke:#3B6D11,color:#C0DD97,rx:8
  classDef roleSpec  fill:#633806,stroke:#854F0B,color:#FAC775,rx:8
  classDef roleAdmin fill:#72243E,stroke:#993556,color:#F4C0D1,rx:8
  classDef roleEmerg fill:#791F1F,stroke:#A32D2D,color:#F7C1C1,rx:8
  classDef permView     fill:#2a3d52,stroke:#185FA5,color:#B5D4F4
  classDef permInteract fill:#1e3d2f,stroke:#3B6D11,color:#C0DD97
  classDef permContent  fill:#3d2c10,stroke:#854F0B,color:#FAC775
  classDef permMod      fill:#3d2c10,stroke:#BA7517,color:#FAC775
  classDef permAccount  fill:#2a1f38,stroke:#7F77DD,color:#CECBF6
  classDef permAdmin    fill:#3a1228,stroke:#993556,color:#F4C0D1
  classDef permAuth     fill:#1a2040,stroke:#534AB7,color:#AFA9EC
  classDef permEmerg    fill:#3a0f0f,stroke:#A32D2D,color:#F7C1C1
  classDef permDeny     fill:#2a0f0f,stroke:#E24B4A,color:#F09595
```

## Files

| File | Description |
|---|---|
| [`MHP_RBAC_Tree.html`](./MHP_RBAC_Tree.html) | Interactive live diagram with Mermaid editor |
| [`rbac-diagram.mmd`](./rbac-diagram.mmd) | Raw Mermaid source file |
| [`rbac-diagram.svg`](./rbac-diagram.svg) | Static SVG export of the diagram |

## Cross-cutting DENY rules

The following operations are **denied for all roles**, regardless of any inherited permissions:

- `✗ update · login nickname` — usernames are immutable once set
- `✗ write ops during maintenance` — platform-wide write lock during maintenance windows

## Permission colour legend

| Colour | Permission category |
|---|---|
| Blue | View |
| Green | Interact (like, comment, subscribe) |
| Orange | Content management (upload, edit, delete) |
| Purple | Account management |
| Pink | Administrative |
| Red | Emergency / DENY |
