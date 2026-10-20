# Codexecutive

A Codex plugin marketplace. It carries one plugin: **Orch Dork**, governed
delegation for Codex. Orch Dork freezes a bounded plan of subagents before any
work starts, keeps every worker inside its own lane with Codex hooks, and
decides each run on host-computed evidence rather than on what a model says it
did.

## Install

```bash
codex plugin marketplace add jwj-eon/codexecutive
codex plugin add orch-dork@codexecutive
```

Then open Codex, review and trust the plugin's five hooks when Codex asks, and
say "enroll this project with Orch Dork" in a chat. The skill walks you through
the rest.

Orch Dork needs a local Codex with the app-server socket and plugin hooks;
without them it runs in advisory mode and refuses to claim a governed result.
Python 3.9 or later must be on PATH.

## What is here

- `plugins/orch-dork/` is the exact runtime package of the qualified
  generation `0.1.0+codex.20261020121054` (runtime package digest
  `19e2238afc702d27f5bc7c758dc7d2e51f44eb27ca8a2dd39a5ecf899d02fab9`).
  Nothing in it is edited after qualification; a new generation replaces the
  directory as a whole.
- `.agents/plugins/marketplace.json` is the marketplace manifest Codex reads.

## Privacy, terms and support

- Privacy: https://orimalabs.com/orch-dork-advisory/privacy/
- Terms: https://orimalabs.com/orch-dork-advisory/terms/
- Support: https://orimalabs.com/orch-dork-advisory/support/

## License

MIT. See `LICENSE` and `plugins/orch-dork/LICENSE`.
