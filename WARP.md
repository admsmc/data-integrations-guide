# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Repository Purpose

Beginner-friendly, FP-oriented guide to modern data integrations with diagrams, runnable examples, and security best practices.

## Repository Architecture

**Main guide**: `docs/data-integrations-modern-best-practices.md` (2117 lines)
- Comprehensive coverage of ETL/ELT, CDC, batch vs streaming, Medallion architecture (Bronze/Silver/Gold)
- Protocol selection (HTTP/REST, Kafka, MQTT, gRPC, SFTP/AS2, ODBC/JDBC)
- Security and governance (PII handling, secrets management, GDPR/CIP/IEC 62443)
- Deployment patterns (iPaaS, serverless, Kubernetes, warehouse-native, on-prem/Hyper-V)
- Industry-specific examples (utilities/energy, Microsoft estate, AMI/MDMS)
- Stack recipes with runnable examples in TypeScript, Python, and Scala
- Organization: TL;DR (lines 18-35) → Core principles → Patterns → Protocols → Stack examples → Deployment → Security
- **Code examples**: Embedded throughout the guide for educational purposes; illustrative of FP patterns but not production-ready or executable without dependencies

**Diagrams**: Mermaid sources in `docs/diagrams/` (.mmd files) with generated PNGs in `docs/images/`
- Only 7 diagrams have .mmd sources; most of the 27 PNG files were created with other tools
- For diagrams with .mmd sources: edit .mmd, regenerate PNG, commit both
- For new diagrams: create .mmd source in `docs/diagrams/` going forward
- Diagrams can be edited/previewed in many editors without Mermaid CLI; CLI only needed for PNG generation before committing
- Diagrams include: medallion flow, ETL vs ELT, batch vs streaming, CDC, security, observability, deployment environments, utilities OT-to-IT, Azure integrations, etc.

**Web interface**: `index.html` uses Docsify to serve content
- Syntax highlighting for JSON, TypeScript, Python, Scala, Bash, Markdown
- Configuration: `basePath: 'docs/'`, `homepage: 'data-integrations-modern-best-practices.md'`
- Renders at root with relative path resolution

**PDF output**: `docs/data-integrations-modern-best-practices.pdf` styled by `docs/pdf.css`
- A4 page size, 16mm margins
- Scales images to page width, wraps code blocks
- Slightly smaller headings for print

## Content Philosophy

**Functional programming first**: Pure core logic, effectful edges, composition
- Examples demonstrate FP principles across TypeScript (fp-ts, Zod), Python (Pydantic, immutable patterns), and Scala (Cats, Circe)
- Emphasize modular, composable components with clear boundaries

**Define terms inline**: Every technical term is explained the first time it appears
- Example: "**ELT** (Extract, Load, Transform: load raw data first, transform later)"

**Short, runnable examples**: Code snippets should be concise and focus on the core idea
- Prefer minimal viable examples over comprehensive frameworks

**Maintain consistency**: When editing content in `docs/data-integrations-modern-best-practices.md`, follow existing patterns:
- Term definitions use format: `**Term** (explanation)` on first occurrence
- Code examples demonstrate FP patterns (pure functions, composition, effects at edges) but are not executable without dependencies

## Common Commands

### Serve locally
```bash
python3 -m http.server 8000
# Then open http://localhost:8000
```

### Regenerate one diagram PNG
Requires [Mermaid CLI](https://github.com/mermaid-js/mermaid-cli) (`npm install -g @mermaid-js/mermaid-cli`):
```bash
mmdc -i docs/diagrams/<diagram-name>.mmd -o docs/images/<diagram-name>.png
```

### Regenerate all diagram PNGs
Only regenerates the 7 diagrams with .mmd sources:
```bash
find docs/diagrams -name '*.mmd' -print0 | while IFS= read -r -d '' f; do 
  out="docs/images/$(basename "${f%.mmd}").png"
  mmdc -i "$f" -o "$out"
done
```

### Create PDF
**Manual**: Open the rendered guide in a Chromium-based browser and Print to PDF
- Load the guide via the local server (http://localhost:8000)
- Use browser's Print dialog with `docs/pdf.css` styles applied
- Styling is auto-applied via the print stylesheet linked in `index.html`
- Save as `docs/data-integrations-modern-best-practices.pdf`

**Automation**: Use browser automation (e.g., Puppeteer/Chrome headless) to generate PDF with `docs/pdf.css` styling

## Key Workflows

**Editing content**
1. Edit `docs/data-integrations-modern-best-practices.md`
2. Serve locally to preview changes
3. Regenerate PDF before committing if content is finalized

**Adding/updating diagrams**
1. Edit or create `.mmd` file in `docs/diagrams/`
2. Regenerate corresponding PNG in `docs/images/`
3. Reference PNG in the main guide with relative path: `![Description](images/<diagram-name>.png)`
4. Commit both `.mmd` and `.png` files

**Testing changes**
- Preview web rendering: serve locally and verify all images, code highlighting, and links work
- Verify PDF rendering: generate PDF and check layout, image scaling, and code block wrapping

## Troubleshooting

**Docsify not rendering when opening index.html**
- Problem: Opening `file://` URLs directly in browser may fail due to CORS restrictions
- Solution: Always serve via HTTP server (`python3 -m http.server 8000`) and access via `http://localhost:8000`

**PDF generation issues**
- Problem: PDF doesn't apply `docs/pdf.css` styling or images don't render
- Solution: Load the guide via HTTP server first (`http://localhost:8000`), then use browser Print to PDF
- Tip: In Chrome, use "Save as PDF" destination and enable "Background graphics" in More settings

**Mermaid CLI installation**
- Install globally: `npm install -g @mermaid-js/mermaid-cli`
- If Puppeteer fails to download Chromium, set: `export PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true` and install Chrome manually
- Alternative: Use online Mermaid editors (mermaid.live) to export PNGs if CLI fails

**Finding content in the guide**
- Use line numbers: TL;DR (18-35), ETL/ELT (72-149), Streaming (152-205), Security (1451-1701), Stack examples (865-1042)
- Search for inline term definitions by looking for `**TermName** (explanation)` pattern
- The guide is educational documentation, not an executable codebase - examples illustrate concepts

## Notes for Contributors

From the guide itself (lines 2113-2117):
- Keep definitions inline as terms first appear
- Keep examples short and runnable where possible
- Maintain an FP-first style: pure core logic, effectful edges, composition

## Navigating the Guide

**Key sections by line range**:
- **Lines 18-35**: TL;DR - comprehensive summary of all guidance
- **Lines 38-69**: Core principles (contracts, schemas, idempotency, observability, composability)
- **Lines 72-149**: ETL vs ELT, Medallion architecture (Bronze/Silver/Gold), SQL's role
- **Lines 152-205**: Batch vs streaming, event design, watermarking, delivery guarantees
- **Lines 688-766**: Utilities & energy industry patterns (OT/IT, AMI, SCADA)
- **Lines 767-858**: Microsoft estate integrations (Azure, Entra ID, Event Hubs, ADF)
- **Lines 865-1042**: Stack recipes with TypeScript, Python, and Scala examples
- **Lines 1451-1701**: Security (encryption, secrets management, webhook verification examples)
- **Lines 1984-2040**: Deployment environments (iPaaS, serverless, Kubernetes, warehouse-native, on-prem/Hyper-V)
- **Lines 2041-2095**: Environments/CI-CD, SLIs/SLOs

**Quick reference**:
- All technical terms are defined inline on first use with format: `**Term** (explanation)`
- Code examples demonstrate FP principles but require dependencies to run
- Examples across 3 stacks show equivalent patterns: TypeScript (fp-ts, Zod), Python (Pydantic), Scala (Cats, Circe)
