<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=ITARCHECK&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="ITARCHECK"/>

# ITARCHECK

### Flags potential ITAR/EAR export-controlled terms and USML categories in code, datasheets, and docs.

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Flags+potential+ITAREAR+exportcontrolled+terms+and+USML+cate;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-itarcheck.svg?color=6b46c1)](https://pypi.org/project/cognis-itarcheck/) [![CI](https://github.com/cognis-digital/itarcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/itarcheck/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Part of the Cognis Neural Suite.*

</div>

```bash
pip install cognis-itarcheck
itarcheck scan .            # → prioritized findings in seconds
```

## Usage — step by step

1. **Install** the screener:

   ```bash
   pip install cognis-itarcheck
   ```

2. **Scan code, datasheets, or docs** for ITAR/EAR export-control indicators and USML categories:

   ```bash
   itarcheck scan ./design-docs --fail-on high
   ```

3. **Emit JSON** (carries `gate_failed` and `fail_on`) for pipelines, and add extra extensions with repeatable `--ext`:

   ```bash
   itarcheck scan ./hdl --ext .vhd --format json | jq '.gate_failed'
   ```

4. **List USML categories** the engine maps against (22 CFR 121.1):

   ```bash
   itarcheck categories
   ```

5. **Gate a build.** Exit `1` when findings meet/exceed `--fail-on`, `0` otherwise. This is a screening aid, not a legal determination:

   ```bash
   itarcheck scan ./src --fail-on medium || echo 'review with an empowered official'
   ```

## Contents

- [Why itarcheck?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why itarcheck?

Flags potential ITAR/EAR export-controlled terms and USML categories in code, datasheets, and docs. — without standing up heavyweight infrastructure.

`itarcheck` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Scan Text
- ✅ Scan Path
- ✅ Summarize
- ✅ Exceeds Threshold
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-itarcheck
itarcheck --version
itarcheck scan .                       # scan current project
itarcheck scan . --format json         # machine-readable
itarcheck scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ itarcheck scan .
  [HIGH    ] ITA-001  example finding             (./src/app.py)
  [MEDIUM  ] ITA-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[capture / scan] --> P[itarcheck<br/>parse + map]
  P --> OUT[report]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`itarcheck` is interoperable with every popular way of using AI:

- **MCP server** — `itarcheck mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `itarcheck scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis itarcheck** | typical tools |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |
<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`itarcheck mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/itarcheck.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/itarcheck.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/itarcheck.git" # uv
pip install cognis-itarcheck                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/itarcheck:latest --help        # Docker
brew install cognis-digital/tap/itarcheck                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/itarcheck/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/itarcheck` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools


**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `itarcheck` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
