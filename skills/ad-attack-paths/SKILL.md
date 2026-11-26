---
name: ad-attack-paths
description: Collect, normalize, analyze and validate Active Directory attack paths including ADCS, SCCM/MECM, MSSQL, Exchange, relay/coercion, ACL/GPO, delegation and shadow credentials.
---

# AD attack paths

Use this skill only for an explicitly authorized task. Persist every step in the task's red-team workflow and collection lifecycle.

## Collection

1. Record the collection run, collector, mode and operator before touching the target.
2. Prefer SharpHound collection methods appropriate to the environment: Container, Group, LocalGroup, GPOLocalGroup, Session, ObjectProps, ACL, Trusts, RDP, DCOM, UserRights, CARegistry, DCRegistry, CertServices, Site, WebClientService, NTLMRegistry, SMBInfo and LdapServices.
3. Add Certipy output for ADCS and ConfigManBearPig/OpenGraph output for SCCM/MECM and its MSSQL topology. Use the normalized `artex-ad-graph-json` adapter for OpenGraph, Exchange or other tool output not represented by native SharpHound JSON.
4. Hash and register every artifact before ingest. Never merge AD principals into the shared external asset inventory.

## Parallel analysis modules

After `ad_collection` completes, run the independent modules in parallel:

- core AD/Kerberos paths, trusts, sessions and local administration;
- ADCS/enterprise PKI and ESC paths;
- SCCM/MECM hierarchy, RBAC, site systems, stored accounts and relay paths;
- MSSQL linked trust, service accounts, impersonation and execution paths;
- Exchange/hybrid identity permissions and exposed services;
- NTLM coercion/relay feasibility for SMB, LDAP/LDAPS, HTTP and ADCS;
- ACL and GPO control paths;
- constrained, unconstrained and resource-based delegation;
- shadow credentials/key-trust paths;
- LAPS, Windows LAPS, gMSA, DPAPI and other credential material.

Mark a module `complete` only when evidence supports the conclusion. Otherwise mark it `blocked` with the exact missing route, credential, collector capability or target control.

## Validation boundary

Read-only discovery, graph calculation and authentication checks may proceed under the task authorization. Before an action that changes target state, stop and record the proposed action and expected impact. This includes writing an ACL or GPO, adding `msDS-KeyCredentialLink`, changing delegation, enrolling or issuing a certificate, creating an SCCM deployment, enabling SQL features, modifying Exchange, establishing persistence, destructive actions, denial of service or bulk data extraction.

After operator approval, capture pre-state, perform the minimum validation, capture evidence, revert the change when possible, and record the post-state. Never report an inferred path as exploited.
