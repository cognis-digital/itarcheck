# Demo 01 — Basic scan of a defense datasheet

A defense subcontractor pushes a component datasheet (`fcu_datasheet.txt`) into
their repository. Before it can be shared with an offshore engineering partner,
their CI pipeline runs ITARCHECK as an export-control screening gate.

The datasheet describes a fire-control / guidance unit and mentions a
rad-hardened space part, a cryptographic module, and an embargoed-destination
shipping note. ITARCHECK should flag these as ITAR (USML Cat XII / XV), EAR
(Cat 5 Part 2), and an OFAC/EAR destination advisory.

## Run it

```bash
# Human-readable table
python -m itarcheck scan demos/01-basic/fcu_datasheet.txt

# Machine-readable JSON for piping into CI / a dashboard
python -m itarcheck scan demos/01-basic/fcu_datasheet.txt --format json

# List the USML categories the engine classifies against
python -m itarcheck categories
```

## Expected behavior

- Several findings are reported, including at least one `high` severity ITAR
  indicator (the guidance/IMU and missile terms).
- Because the default `--fail-on` is `high`, the process exits with code `1`,
  failing the CI gate.
- Re-running with `--fail-on low` keeps the failing exit; running a clean file
  exits `0`.

## Caveat

ITARCHECK is a screening aid, not a legal determination. Every finding must be
reviewed by an empowered official before any export decision is made.
