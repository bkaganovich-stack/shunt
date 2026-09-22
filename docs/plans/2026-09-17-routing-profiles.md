# Editable routing profiles

User-approved specification: correct routing priorities, current ru-blocked, inspectable service sets and diagnosis of missed destinations; profile-scoped editing/reset, one-step undo, modified badge, copies. No frontend build or new runtime dependencies. Preserve unrelated settings/manual rules. Do not deploy to household gateway.

## Task 1: Unified routing model
Create profiles.py pure model with four builtin profiles, persisted profile_overrides and custom_profiles, metadata/list/service catalogs, shared ordered rules used by global/device/group routing and route_test. Explicit ru-available-only-inside first, confirmed discoveries/service/domain blocked before broad geoip:ru/category-ru; preserve global manual precedence and private/proxy protection, emergency direct. No duplicate antifilter list. Profile settings: tunnel_lists allowlisted geosite and geoip refs, services allowlisted IDs, use_discovered bool, apple_vpn bool, realtime_direct bool; default_route direct/tunnel editable except emergency direct. Name max 80. Legacy toggles migrate through effective settings without unrelated side effects. One-step profile-local history for save/reset, copies get stable IDs, builtins cannot delete. Model APIs catalog(settings), effective(settings,id), update(settings,id,config), reset(settings,id), undo(settings,id), clone(settings,id,name). Mutators return a deep-copied new settings document. Parent will integrate HTTP APIs. Add meaningful tests for priorities, source policies, modified/reset/undo preserving global settings.

## Task 2: Diagnostics and HTTP integration
Authenticated profile catalogue/edit/reset/undo/copy/preview APIs. Validate before persistence, restore settings on failure, apply only if profile used globally/by a device/group. Diagnostic explicit host action compares public direct and tunnel HTTPS using bounded probes, pin validated resolved public IP, prohibit redirects/rebinding/internal networks and shell interpolation; no automatic application, report transport/HTTP evidence with uncertainty. Applying confirmed recommendation is explicit, profile-local and undoable. Upgrade generic probe classification to reject 5xx/429 and avoid confidently claiming site down. Shared route preview accepts profile + optional config and source/device, does not mutate.

## Task 3: Static frontend
Profile editor accessible desktop/mobile dialog tabs behavior/lists/check. Catalogue is dynamic including copied profiles. Modified badge. Save, Reset to defaults, Undo last change, Copy with name; meaningful errors and pending state. Diagnostic evidence and explicit Apply recommendation. RU/EN keys. No build.

## Task 4: Verification
Full Python + JS tests, syntax checks, package manifest includes new files, browser desktop/mobile/dark/light fixture. Independent code review, focused fixes. Document model, limits and validation. Retain worktree for review; no live install.
