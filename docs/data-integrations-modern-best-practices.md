# Modern Data Integrations: A Beginner-Friendly Guide

This guide explains how to build reliable, modular, and composable data integrations. It defines every technical term as it appears, includes short examples, and links you to trusted resources for learning more. It emphasizes **functional programming** (FP: writing programs by composing small, pure functions that avoid shared mutable state) and three stacks: **TypeScript**, **Python**, and **Scala**.

## Who this is for

- Engineers and analysts who want to connect data sources to destinations in a robust way.
- Teams adopting modern patterns like **ELT** (Extract, Load, Transform: load raw data first, transform later), **CDC** (Change Data Capture: streaming row-level changes from source databases), and **event-driven** (systems that react to events rather than polling on a schedule) architectures.

## How to read this guide

- Every term is defined inline the first time it appears.
- Examples are short and focus on the core idea.
- Pros and cons are listed so you can make pragmatic choices.

---

## TL;DR

- Prefer **data contracts** (a machine-and-human readable agreement about schema and semantics) from day one using **schemas** (structured definitions of data fields and types) like [JSON Schema](https://json-schema.org/), or code-first schema libraries ([Zod](https://zod.dev/) for TypeScript, [Pydantic](https://docs.pydantic.dev/) for Python, [Circe](https://circe.github.io/circe/) for Scala).
- Choose **batch** (process data in chunks on a schedule) for simplicity; choose **streaming** (process events continuously as they arrive) for freshness or **low-latency** requirements (low-latency: results are available very quickly).
- Favor **ELT** (load raw, transform in the warehouse or lakehouse) for analytics; use **ETL** (Extract, Transform, Load: transform before loading) for operational sinks (systems you write to for operations) that require cleaned data upfront.
- Use **CDC** (Change Data Capture) when you need near-real-time **replication** (keeping copies of data in sync) without **full-table scans** (reading the entire table).
- Make every step **idempotent** (safe to re-run without changing the final result) and **observable** (emit metrics, logs, and traces that show what happened).
- **Orchestrate** (coordinate and schedule tasks) with workflow tools like [Dagster](https://dagster.io/) or [Temporal](https://temporal.io/), and manage transformations with [dbt](https://www.getdbt.com/) (data build tool) or [Spark](https://spark.apache.org/) (distributed compute engine).
- Test with **property-based testing** (automatically generate varied inputs to test properties), **contract tests** (verify producer and consumer agree on schema), and end-to-end checks.
- Secure with **least privilege** (grant only the minimal access needed), **encryption at rest and in transit** (data is encrypted on disk and over the network), and **secrets management** (safe storage for credentials).

---

## Core principles and why they matter

### Data contracts

A clear, versioned agreement on fields and meaning. Prevents **breaking changes** (changes that cause dependent systems to fail).

**Tools**: [JSON Schema](https://json-schema.org/), [OpenAPI](https://www.openapis.org/) (HTTP API description format), [Protocol Buffers](https://protobuf.dev/) (binary schema with code generation).

### Schemas and validation

Validate **at the edge** (right where data enters your system). TypeScript [Zod](https://zod.dev/), Python [Pydantic](https://docs.pydantic.dev/), Scala [Circe](https://circe.github.io/circe/) ensure bad inputs **fail fast** (fail early with clear errors).

### Idempotency

Design **upserts** (update or insert depending on existence) and merges so retries do not duplicate data. Use **natural keys** (business-meaningful unique identifiers) or **surrogate keys** (system-generated identifiers) plus **deduplication** (removing duplicates).

### Observability

Emit **metrics** (numeric measurements), **logs** (text records of events), and **traces** (end-to-end request timelines). Use [OpenTelemetry](https://opentelemetry.io/) (open standard for telemetry) to instrument consistently.

### Composability

Build small **pure functions** (no side effects) and **compose** them (combine functions to build behavior). Keep **I/O** (input/output like network and disk) at the boundaries.

### Backpressure and retries

**Backpressure** (slowing intake when downstream is slow) protects systems. Use **exponential backoff** (increasing retry delays) and **circuit breakers** (temporarily stop calls to a failing service).

### Security and governance

Classify data (tag by sensitivity), handle **PII** (personally identifiable information) properly, and **audit access** (record who did what and when).

---

## Choosing patterns: when to use what

### ETL vs ELT

![ETL vs ELT Architecture](images/etl-vs-elt.png)

#### ETL (transform before load)

Good when the destination must receive clean, modeled data.

- **Pros**: faster queries on arrival, smaller storage.
- **Cons**: less raw history, harder to re-model later.

**Learn more**: [dbt docs](https://docs.getdbt.com/), [Snowflake best practices](https://docs.snowflake.com/en/user-guide/data-load-best-practices), [BigQuery best practices](https://cloud.google.com/bigquery/docs/best-practices-loading-data).

#### ELT (load then transform)

Good for analytics and agility.

- **Pros**: keeps raw history, flexible transformations.
- **Cons**: requires warehouse or lake compute and governance.

---

### Batch vs streaming

![Batch vs Streaming Processing](images/batch-vs-streaming.png)

#### Batch

Run hourly or daily.

- **Pros**: simple, cost-efficient.
- **Cons**: latency, potential for large **backfills** (reprocessing historical data).

#### Streaming

Continuous event processing.

- **Pros**: low latency, incremental updates.
- **Cons**: more moving parts and operational complexity.

---

### CDC (Change Data Capture)

![CDC Architecture](images/cdc.png)

Reads database **change logs** (append-only records of row changes).

- **Pros**: near-real-time sync, avoids full scans.
- **Cons**: requires log access and careful **schema evolution** (changing schemas without breaking consumers).

**Learn more**: [Debezium](https://debezium.io/), [Kafka Connect](https://docs.confluent.io/platform/current/connect/index.html).

---

### Webhooks vs polling

![Webhooks vs Polling](images/webhook-vs-polling.png)

#### Webhook

Source sends HTTP POST to you on events.

- **Pros**: immediate updates.
- **Cons**: need public endpoints and **signature verification** (checking authenticity).

#### Polling

You fetch on a schedule.

- **Pros**: simpler networking.
- **Cons**: higher latency and risk of **rate limits** (limits on request frequency).

---

### Orchestrators and dataflow engines

#### Orchestrator

Schedules and tracks tasks: [Dagster](https://dagster.io/), [Prefect](https://www.prefect.io/), [Temporal](https://temporal.io/).

- **Pros**: visibility and retries.
- **Cons**: learning curve.

#### Dataflow engine

Executes transformations at scale: [Spark](https://spark.apache.org/), [Flink](https://flink.apache.org/).

- **Pros**: scalable compute.
- **Cons**: cluster and resource management.

---

## Legacy integration types: SFTP, batch files, flat files, EDI

Legacy integrations are still everywhere. Treat them with the same rigor: contracts, validation, idempotency, observability, and security.

Key patterns and guardrails
- SFTP (Secure File Transfer Protocol: encrypted file transfer over SSH)
  - Do: use key-based auth (authentication with SSH keys), IP allowlists, and chrooted users (restrict users to a directory).
  - Naming contract: include system, entity, date, sequence, and checksum, e.g. `acme_customers_2025-11-05_seq-00023_crc32-1A2B3C4D.csv`.
  - Atomic writes: upload to a temp name, then rename; avoid partial reads.
  - Idempotency: derive a content hash (e.g., SHA-256) or parse sequence numbers; store digests in a processed table to avoid re-ingest.
  - PGP (Pretty Good Privacy) encryption at rest: require `.gpg` files; decrypt server-side; validate signature (proves sender and integrity).
  - Retries: exponential backoff; quarantine (move to a safe folder) on repeated failures.
- Batch CSV/TSV (comma/tab-separated values)
  - Contract: provide a CSV schema (column names, types, formats, delimiters, newline style). Enforce via a validator before landing.
  - Common pitfalls: BOM (byte-order mark), stray delimiters, embedded newlines, inconsistent quoting. Normalize with a robust CSV parser.
  - Incremental loads: use high-water marks (max timestamp or ID) or explicit sequence files.
  - Deduplication: use natural keys + windowed dedupe (e.g., last 7 days) or content hashes.
- Fixed-width files (columns defined by start/end positions)
  - Contract: publish a layout spec (column offsets, types, padding). Reject rows with misaligned lengths.
  - Testing: create golden samples (known-good files) and fuzz tests (randomized variations) to catch parser drift.
- EDI (Electronic Data Interchange, e.g., X12 850/810, EDIFACT)
  - Use a translator (EDI parser/mapper) to convert to JSON/CSV.
  - Acknowledge via functional acknowledgments (997/999: confirmations of receipt and syntactic validity).
  - Idempotency: ISA/GS/ST control numbers (unique transaction identifiers) are your keys; track them.
- Email-driven drops
  - Avoid if possible. If required: use secure inboxes with strict allowlists; parse attachments; verify DKIM/SPF (email authentication mechanisms).

Control points and automations
- Landing zones (a.k.a. bronze): write-once, append-only, with metadata: `source`, `received_at`, `checksum`, `pgp_fingerprint`.
- Validation layers: schema checks, referential integrity (FKs between files), domain rules. Send detailed error reports to partners.
- Replay/backfill: keep raw files; reprocess deterministically for audits.
- Partner scorecards: track on-time delivery, error rates, file sizes, schema drift; share dashboards.

Mermaid diagram: SFTP batch intake
![SFTP batch intake](images/sftp-intake.png)

Operational checklist
- Rotate SSH keys regularly; enforce strong ciphers; disable password logins.
- Enforce file size limits; reject unexpected mime types; scan attachments for malware.
- Maintain a per-partner runbook (who to contact, SLAs, file contracts, escalation steps).
- Version contracts; run contract tests in CI with sample files.
- Emit metrics: files received, bytes, validation failures, dedupe drops, processing latency, partner SLA breaches.

### Practical examples: SFTP batch processing

#### TypeScript: SFTP + CSV validation

**Tools**: [ssh2-sftp-client](https://www.npmjs.com/package/ssh2-sftp-client) (SFTP), [csv-parse](https://csv.js.org/parse/) (CSV parser), [Zod](https://zod.dev/) (validation).

```typescript
import SFTPClient from "ssh2-sftp-client";
import { parse } from "csv-parse/sync";
import { z } from "zod";
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";

const CustomerRow = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string().email(),
  created_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/)
});

type CustomerRow = z.infer<typeof CustomerRow>;

async function processSFTPBatch() {
  const sftp = new SFTPClient();
  await sftp.connect({
    host: "sftp.partner.com",
    privateKey: await fs.readFile("/secrets/sftp_key", "utf8"),
    username: "integration_user"
  });

  const files = await sftp.list("/inbox");
  
  for (const file of files.filter(f => f.name.endsWith(".csv"))) {
    const remotePath = `/inbox/${file.name}`;
    const localPath = `/tmp/${file.name}`;
    
    // Download atomically
    await sftp.get(remotePath, localPath);
    
    // Compute checksum for idempotency
    const content = await fs.readFile(localPath);
    const hash = crypto.createHash("sha256").update(content).digest("hex");
    
    // Check if already processed (pseudo-code)
    // if (await isProcessed(hash)) continue;
    
    // Parse and validate
    const records = parse(content, { columns: true, skip_empty_lines: true });
    const validated: CustomerRow[] = [];
    
    for (const rec of records) {
      const result = CustomerRow.safeParse(rec);
      if (result.success) {
        validated.push(result.data);
      } else {
        console.error("Validation failed:", result.error, rec);
      }
    }
    
    // Store with metadata
    await fs.writeFile(
      `/landing/${file.name}.json`,
      JSON.stringify({ hash, received_at: new Date().toISOString(), rows: validated }),
      "utf8"
    );
    
    // Archive original
    await sftp.rename(remotePath, `/archive/${file.name}`);
    
    console.log(`Processed ${file.name}: ${validated.length} rows, hash=${hash}`);
  }
  
  await sftp.end();
}

processSFTPBatch().catch(err => console.error(err));
```

**Pros**:
- Type-safe validation at runtime.
- Idempotency via content hash.
- Atomic operations (download, rename).

**Cons**:
- Single-threaded; scale horizontally for high volume.
- SSH key management requires external secrets store.

#### Python: SFTP + Pandas batch processing

**Tools**: [paramiko](https://www.paramiko.org/) (SSH/SFTP), [Pandas](https://pandas.pydata.org/) (CSV), [Pydantic](https://docs.pydantic.dev/) (validation).

```python
import hashlib
import paramiko
import pandas as pd
from pathlib import Path
from pydantic import BaseModel, EmailStr, ValidationError
from datetime import datetime

class CustomerRow(BaseModel):
    id: str
    name: str
    email: EmailStr
    created_date: str  # YYYY-MM-DD

def process_sftp_batch():
    key = paramiko.RSAKey.from_private_key_file("/secrets/sftp_key")
    transport = paramiko.Transport(("sftp.partner.com", 22))
    transport.connect(username="integration_user", pkey=key)
    sftp = paramiko.SFTPClient.from_transport(transport)
    
    for file_attr in sftp.listdir_attr("/inbox"):
        if not file_attr.filename.endswith(".csv"):
            continue
        
        remote_path = f"/inbox/{file_attr.filename}"
        local_path = f"/tmp/{file_attr.filename}"
        
        # Download
        sftp.get(remote_path, local_path)
        
        # Compute checksum
        with open(local_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Check idempotency (pseudo-code)
        # if is_processed(file_hash): continue
        
        # Parse CSV with Pandas
        df = pd.read_csv(local_path)
        validated = []
        
        for _, row in df.iterrows():
            try:
                customer = CustomerRow.model_validate(row.to_dict())
                validated.append(customer.model_dump())
            except ValidationError as e:
                print(f"Validation failed: {e}")
        
        # Store with metadata
        landing = {
            "hash": file_hash,
            "received_at": datetime.utcnow().isoformat(),
            "rows": validated
        }
        Path("/landing").mkdir(exist_ok=True)
        pd.DataFrame(landing["rows"]).to_parquet(
            f"/landing/{file_attr.filename}.parquet", index=False
        )
        
        # Archive
        sftp.rename(remote_path, f"/archive/{file_attr.filename}")
        
        print(f"Processed {file_attr.filename}: {len(validated)} rows, hash={file_hash}")
    
    sftp.close()
    transport.close()

if __name__ == "__main__":
    process_sftp_batch()
```

**Pros**:
- Pandas handles messy CSVs well; Parquet for fast analytics.
- Pydantic validates per-row with clear error messages.

**Cons**:
- Paramiko SSH setup is verbose; consider higher-level wrappers.
- Memory usage for large files; chunk with `chunksize` parameter.

#### Scala: SFTP + fs2 streaming

**Tools**: [sshj](https://github.com/hierynomus/sshj) (SFTP), [fs2](https://fs2.io/) (streaming), [Circe](https://circe.github.io/circe/) (JSON), [kantan.csv](https://nrinaudo.github.io/kantan.csv/) (CSV).

```scala
import cats.effect.{IO, IOApp}
import fs2.{Stream, io, text}
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.sftp.SFTPClient
import kantan.csv._
import kantan.csv.ops._
import java.security.MessageDigest

case class CustomerRow(id: String, name: String, email: String, createdDate: String)

object SFTPBatchProcessor extends IOApp.Simple {
  def computeSHA256(bytes: Array[Byte]): String =
    MessageDigest.getInstance("SHA-256")
      .digest(bytes)
      .map("%02x".format(_))
      .mkString

  def run: IO[Unit] = {
    val ssh = new SSHClient()
    ssh.loadKnownHosts()
    ssh.connect("sftp.partner.com")
    ssh.authPublickey("integration_user", "/secrets/sftp_key")
    val sftp = ssh.newSFTPClient()

    val files = sftp.ls("/inbox").asScala.filter(_.getName.endsWith(".csv"))

    Stream.emits(files.toSeq)
      .evalMap { file =>
        val remotePath = s"/inbox/${file.getName}"
        val localPath = s"/tmp/${file.getName}"

        for {
          _ <- IO(sftp.get(remotePath, localPath))
          bytes <- IO(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(localPath)))
          hash = computeSHA256(bytes)
          // Check idempotency: if (isProcessed(hash)) return
          rows <- IO {
            new String(bytes).asCsvReader[CustomerRow](rfc.withHeader)
              .collect { case Right(row) => row }
              .toList
          }
          _ <- IO.println(s"Processed ${file.getName}: ${rows.size} rows, hash=$hash")
          _ <- IO(sftp.rename(remotePath, s"/archive/${file.getName}"))
        } yield ()
      }
      .compile
      .drain
      .guarantee(IO(sftp.close()) >> IO(ssh.disconnect()))
  }
}
```

**Pros**:
- Purely functional with safe resource handling.
- Backpressure-aware streaming for large file sets.

**Cons**:
- SSHJ is Java-based; setup is verbose.
- CSV parsing with kantan.csv requires schema definition; less forgiving than Pandas.

**Learn more**: [ssh2-sftp-client](https://www.npmjs.com/package/ssh2-sftp-client), [paramiko docs](https://www.paramiko.org/), [sshj](https://github.com/hierynomus/sshj), [kantan.csv](https://nrinaudo.github.io/kantan.csv/).

## Enterprise integration scenarios (banking, payroll, PSP, ERP/HRIS)

This section outlines common enterprise integrations, with contracts, security, idempotency, pagination, and reconciliation patterns.

### Banking (accounts, payments, statements)
- Channels
  - Webhooks/API (events like payment posted, return received), SFTP statement files (ISO 20022 camt.053/camt.054, BAI2, OFX, CSV), portal downloads.
  - Payments: ACH (NACHA files for credits/debits), wires (Fedwire/ISO 20022 pacs.008/pacs.002), RTP (real-time payments) events.
- Contracts and identifiers
  - Use bank-provided unique references (trace number, end-to-end ID, payment ID) as idempotency keys; combine date + amount + counterparty as fallback.
  - For files, include naming contracts and checksums; require PGP encryption for SFTP.
- Reconciliation
  - Two-way: match internal ledger entries to bank transactions by reference and amount/date; handle timing differences (posting vs value date).
  - Returns and exceptions: ACH return codes (R01–R85), chargebacks, reversals; implement a state machine and retry/backoff policies.
- Security
  - mTLS/IP allowlists for APIs; PGP for files; signature verification for webhooks; strict secrets management.
  - Compliance: OFAC screening, audit logs, least privilege, separation of duties for approvals.
- Latency/SLAs
  - Intraday vs end-of-day statements; cut-off times; ensure idempotent backfills when late files arrive.

Mermaid: Bank events + statements
![Bank events and statements](images/bank-events.png)

### Payroll (providers, HRIS, GL)
- Flows
  - Employee/HR data (HRIS: Workday, BambooHR), time & attendance, earnings/deductions, tax withholdings, payroll runs, GL exports.
  - Transports: SFTP CSV/fixed-width, provider APIs, webhooks for run status.
- Contracts
  - Versioned file specs (columns/offsets), schemas for API payloads; golden sample files; property-based tests for edge cases (overtime, bonuses, retro pay).
- PII/PHI handling
  - SSN, bank routing/account numbers, addresses: encrypt at rest, redact in logs, strict retention (need-to-know), DSRs (deletion/access) support.
- Idempotency & reconciliation
  - Run ID + pay period as idempotency keys; per-employee unique keys (employee_id + paycheck_date).
  - Reconcile totals (gross, net, taxes) against provider run reports; handle adjustments and reversals.
- Security & compliance
  - SOC 2/ISO attestations from providers; SFTP key rotation; audit trails; approvals workflow separation.

### PSP/Card processing (Stripe/Adyen-like), payouts
- Events: authorization, capture, refund, dispute/chargeback, payouts/settlements; fees and FX.
- Pattern: process webhooks for real-time events; reconcile with daily payout files over SFTP.
- Idempotency: provider event IDs + type; deterministically derive transfer IDs; dedupe on replay.
- Reconciliation: sum captured - refunds - fees = net payout; match by payout ID/date.

### ERP/Finance/CRM (master data and transactions)
- Master data sync
  - Parties/customers/vendors/products; use CDC where possible or API pagination by updated_at; cursors for large sets.
  - Contracts: strict schemas; reject unknowns, log schema drift.
- Transactions
  - Invoices, bills, journal entries; ensure double-entry integrity; batch windows with idempotent upserts.
- Security
  - OAuth/OIDC for APIs, mTLS for internal links, PGP for file exchanges; role-based access and environment scoping (dev/test/prod tenants).

Red flags and mitigations
- Unversioned file specs → introduce version field and publish samples; validate strictly.
- No unique identifiers → derive deterministic keys and keep a manifest for dedupe.
- Large late-arriving files → design for replay/backfill; partition by date and recompute safely.
- Partner outages → dead-letter queues, retry schedules, and clear runbooks with contacts.

## Reference blueprint (conceptual)

![Reference Architecture Blueprint](images/reference-blueprint.png)

---

## Stack recipes with short examples

### TypeScript recipe: validate, transform, and write safely

**Tools**: [Zod](https://zod.dev/) (schema validation), [fp-ts](https://gcanti.github.io/fp-ts/) (functional utilities), node fetch or axios (HTTP client).

**Example**: validate an API record, transform it, and write to disk. Idempotency here is demonstrated by deriving a stable filename from a natural key so reruns overwrite the same file.

```typescript
import { z } from "zod";
import { pipe } from "fp-ts/function";
import * as E from "fp-ts/Either";
import * as fs from "node:fs/promises";

const User = z.object({
  id: z.string(),
  email: z.string().email(),
  createdAt: z.string() // ISO timestamp
});

type User = z.infer<typeof User>;

const transformUser = (u: User) => ({
  id: u.id,
  email_domain: u.email.split("@")[1],
  created_date: u.createdAt.split("T")[0]
});

const parseUser = (data: unknown) =>
  E.tryCatch(
    () => User.parse(data),
    e => new Error(String(e))
  );

async function main() {
  const res = await fetch("https://example.com/api/user/123");
  const json = await res.json();

  const result = parseUser(json);
  if (E.isRight(result)) {
    const safe = transformUser(result.right);
    const outPath = `./out/user-${safe.id}.json`;
    await fs.mkdir("./out", { recursive: true });
    await fs.writeFile(outPath, JSON.stringify(safe) + "\n", "utf8");
    console.log("Wrote", outPath);
  } else {
    console.error("Validation failed", result.left.message);
  }
}

main().catch(err => console.error(err));
```

#### Pros

- Strong types and runtime validation reduce bad data.
- Composable pure functions make logic easy to test.

#### Cons

- Node-based pipelines may need extra tooling for heavy compute.
- Requires discipline to separate pure logic from I/O.

**Learn more**: [Zod](https://zod.dev/), [fp-ts](https://gcanti.github.io/fp-ts/), [KafkaJS](https://kafka.js.org/), [Temporal TypeScript SDK](https://docs.temporal.io/typescript), [dbt Core](https://docs.getdbt.com/).

---

### Python recipe: ingest, validate, and batch to Parquet

**Tools**: [Pydantic](https://docs.pydantic.dev/) (validation), [Requests](https://requests.readthedocs.io/) (HTTP), [Pandas](https://pandas.pydata.org/) (tabular data), [PyArrow Parquet](https://arrow.apache.org/docs/python/parquet.html) (columnar file format optimized for analytics).

**Example**: fetch, validate, transform, and save as Parquet.

```python
from datetime import datetime
from typing import List
import requests
import pandas as pd
from pydantic import BaseModel, EmailStr, ValidationError

class User(BaseModel):
    id: str
    email: EmailStr
    created_at: datetime

def transform(u: User) -> dict:
    return {
        "id": u.id,
        "email_domain": u.email.split("@")[1],
        "created_date": u.created_at.date().isoformat(),
    }

def run():
    r = requests.get("https://example.com/api/users")
    r.raise_for_status()
    raw = r.json()
    out: List[dict] = []
    for item in raw:
        try:
            u = User.model_validate(item)
            out.append(transform(u))
        except ValidationError as e:
            print("Validation failed:", e)

    df = pd.DataFrame(out)
    df.to_parquet("out/users.parquet", index=False)

if __name__ == "__main__":
    run()
```

#### Pros

- Rich ecosystem for data work (Pandas, PyArrow, Dagster, Prefect, dbt).
- Pydantic makes validation straightforward.

#### Cons

- Performance tuning may be needed for very large datasets.
- Virtual environment and version management require care.

**Learn more**: [Pydantic](https://docs.pydantic.dev/), [Dagster](https://dagster.io/), [Prefect](https://www.prefect.io/), [Great Expectations](https://greatexpectations.io/), [dbt Core](https://docs.getdbt.com/).

---

### Scala recipe: functional streaming with fs2 and Circe

**Tools**: [cats-effect](https://typelevel.org/cats-effect/) (FP effects), [fs2](https://fs2.io/) (functional streams), [Circe](https://circe.github.io/circe/) (JSON), [Spark](https://spark.apache.org/) for big data transforms.

**Example**: decode and transform a small JSON stream.

```scala
import cats.effect.{IO, IOApp}
import fs2.Stream
import io.circe._, io.circe.parser._

final case class User(id: String, email: String, createdAt: String)

object Main extends IOApp.Simple {
  def transform(u: User): Map[String, String] =
    Map(
      "id" -> u.id,
      "email_domain" -> u.email.split("@")(1),
      "created_date" -> u.createdAt.takeWhile(_ != 'T')
    )

  val rawJson = List(
    """{"id":"1","email":"a@example.com","createdAt":"2024-01-01T12:00:00Z"}"""
  )

  def run: IO[Unit] =
    Stream
      .emits(rawJson)
      .evalMap { s =>
        IO.fromEither(decode[User](s)).attempt.flatMap {
          case Right(u) => IO.println(transform(u))
          case Left(e)  => IO.println(s"Validation failed: ${e.getMessage}")
        }
      }
      .compile
      .drain
}
```

#### Pros

- Strong FP abstractions enable safe, composable pipelines.
- Excellent for streaming and backpressure-aware processing.

#### Cons

- Steeper learning curve for FP libraries.
- Spark integration adds operational overhead.

**Learn more**: [cats-effect](https://typelevel.org/cats-effect/), [fs2](https://fs2.io/), [Circe](https://circe.github.io/circe/), [Spark Structured Streaming](https://spark.apache.org/docs/latest/structured-streaming-programming-guide.html).

---

## Data quality and data contracts

![Data Quality Layers and Schema Evolution](images/data-quality.png)

### Expectations

**Expectations** (machine-checked assertions about data): e.g., **column not null** (no missing values) or **values in a set** (only allowed values).

**Example with Great Expectations** ([Python data quality framework](https://greatexpectations.io/)):

```python
import pandas as pd
from great_expectations.dataset import PandasDataset

df = pd.DataFrame({"id":[1,2], "email":["a@example.com","b@example.com"]})
gdf = PandasDataset(df)
gdf.expect_column_values_to_not_be_null("id")
gdf.expect_column_values_to_match_regex("email", r".+@.+")
result = gdf.validate()
print(result["success"])
```

### Schema evolution

Version schemas and use **backward compatibility** (new data still works with old consumers). Keep a **changelog** (record of changes).

**Learn more**: [Schema Registry docs](https://docs.confluent.io/platform/current/schema-registry/index.html), [Avro schema evolution](https://avro.apache.org/docs/current/spec.html#Schema+Resolution).

---

## Testing strategies

![Testing Pyramid for Data Pipelines](images/testing.png)

- **Unit tests** (test individual functions) on pure transforms.
- **Property-based tests** (generate varied inputs to test general properties).
- **Contract tests** (verify producer and consumer agree on schema and fields).
- **End-to-end tests** (run the entire pipeline on a small sample).

**Tools**: [fast-check](https://fast-check.dev/) (TypeScript), [Hypothesis](https://hypothesis.readthedocs.io/) (Python), [ScalaCheck](https://scalacheck.org/) (Scala).

---

## Observability basics

### Logging and data persistence rules

- Do not log raw PII (personally identifiable information). Redact or hash with a keyed HMAC if correlation is required; never log secrets, API keys, access tokens, private keys, or full card numbers.
- Use structured logs (JSON) with stable keys; include correlation IDs (unique request identifiers) and partner/source identifiers; avoid dumping entire payloads.
- Adopt log levels: DEBUG (dev-only, feature-flagged), INFO (high-level flow), WARN (recoverable anomalies), ERROR (actionable failures). Guard DEBUG in production.
- Set retention policies by data class: e.g., 7–14 days for detailed app logs, 30–90 days for audit logs; longer only if legally required.
- Implement sampling for high-volume success logs; never sample error logs. Ensure sampling decisions preserve traceability.
- Centralize logs in a secure store; restrict access by least privilege; enable immutability/legal holds for audit streams.
- Add data lineage/context fields instead of content: file_name, checksum, record_count, schema_version, received_at.

### Idempotency and pagination rules

Idempotency (safe to retry without changing the final result)
- All ingestion endpoints and batch jobs must be idempotent. Use idempotency keys (deterministically derived identifiers) or natural keys + upsert semantics.
- For file-based intake, compute content digests (e.g., SHA-256) and persist a processed manifest; on retry, skip duplicates.
- For APIs, require headers like `Idempotency-Key` and store request hashes + result hashes for the retry window (e.g., 24–72 hours).
- Avoid non-deterministic operations inside idempotent handlers (e.g., "now" timestamps without passing them as inputs); if needed, pass a fixed clock or include timestamps in the key.

Pagination (consistent traversal of large datasets)
- Prefer cursor-based pagination (an opaque token representing position) over offset-based pagination for consistency and performance.
- For "delta" backfills, paginate by a stable sort key (e.g., updated_at, id) and use ">= last_seen" semantics to avoid gaps; dedupe on the consumer side.
- Enforce maximum page sizes; document rate limits; backoff on 429/503 responses; support resume on failure with the last cursor.
- When combining pagination with idempotency, include the page cursor or last-seen checkpoint in the idempotency key so retries don't create duplicates.

#### Practical examples: idempotency and pagination

##### TypeScript: idempotent API handler with request tracking

```typescript
import { createHash } from "node:crypto";
import { Request, Response } from "express";

// Pseudo-store for demo; use Redis or DB in production
const requestCache = new Map<string, { status: number; body: any }>();
const TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function computeIdempotencyKey(req: Request): string {
  const key = req.headers["idempotency-key"] as string;
  if (key) return key;
  
  // Fallback: hash method + path + body
  const hash = createHash("sha256")
    .update(`${req.method}:${req.path}:${JSON.stringify(req.body)}`)
    .digest("hex");
  return hash;
}

export async function idempotentHandler(req: Request, res: Response) {
  const idempotencyKey = computeIdempotencyKey(req);
  
  // Check cache
  if (requestCache.has(idempotencyKey)) {
    const cached = requestCache.get(idempotencyKey)!;
    return res.status(cached.status).json(cached.body);
  }
  
  // Process request
  try {
    const result = await processRequest(req.body);
    const response = { status: 200, body: result };
    
    // Cache result with TTL
    requestCache.set(idempotencyKey, response);
    setTimeout(() => requestCache.delete(idempotencyKey), TTL_MS);
    
    res.status(200).json(result);
  } catch (err) {
    // Don't cache errors; allow retry
    console.error("Request failed:", err);
    res.status(500).json({ error: "Internal error" });
  }
}

async function processRequest(body: any): Promise<any> {
  // Your business logic here
  return { id: "123", status: "processed" };
}
```

**Key points**:
- Idempotency key from header or derived from request content.
- Cache successful responses for 24 hours; don't cache errors.
- Replay cached response immediately on duplicate.

##### Python: cursor-based pagination with resumable polling

```python
import requests
import time
from typing import Optional, List, Dict, Any

BASE_URL = "https://api.partner.com/v1/customers"
MAX_RETRIES = 3
BACKOFF_SECONDS = 2

def fetch_all_customers() -> List[Dict[str, Any]]:
    """Fetch all customers using cursor-based pagination."""
    all_customers = []
    cursor: Optional[str] = None
    
    while True:
        customers, next_cursor = fetch_page(cursor)
        all_customers.extend(customers)
        
        if not next_cursor:
            break  # No more pages
        
        cursor = next_cursor
        time.sleep(0.1)  # Rate limit courtesy
    
    return all_customers

def fetch_page(cursor: Optional[str], retry: int = 0) -> tuple[List[Dict], Optional[str]]:
    """Fetch a single page; returns (records, next_cursor)."""
    params = {"limit": 100}
    if cursor:
        params["cursor"] = cursor
    
    try:
        resp = requests.get(BASE_URL, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        
        return data.get("customers", []), data.get("next_cursor")
    
    except (requests.HTTPError, requests.Timeout) as e:
        if retry < MAX_RETRIES:
            wait = BACKOFF_SECONDS * (2 ** retry)
            print(f"Error fetching page, retry {retry + 1}/{MAX_RETRIES} in {wait}s")
            time.sleep(wait)
            return fetch_page(cursor, retry + 1)
        raise

if __name__ == "__main__":
    customers = fetch_all_customers()
    print(f"Fetched {len(customers)} customers")
```

**Key points**:
- Cursor is opaque; passed to next request.
- Exponential backoff on transient errors.
- Resumable: if process crashes, restart with last known cursor.

##### Scala: idempotent file processing with manifest

```scala
import cats.effect.{IO, Ref}
import java.security.MessageDigest
import scala.collection.mutable

case class ProcessedManifest(hashes: Set[String])

object IdempotentFileProcessor {
  def computeSHA256(bytes: Array[Byte]): String =
    MessageDigest.getInstance("SHA-256")
      .digest(bytes)
      .map("%02x".format(_))
      .mkString

  def processFile(filePath: String, manifestRef: Ref[IO, ProcessedManifest]): IO[Unit] =
    for {
      bytes <- IO(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath)))
      hash = computeSHA256(bytes)
      manifest <- manifestRef.get
      
      _ <- if (manifest.hashes.contains(hash)) {
        IO.println(s"File $filePath already processed (hash=$hash), skipping")
      } else {
        for {
          _ <- IO.println(s"Processing $filePath (hash=$hash)")
          _ <- doProcessing(bytes)
          _ <- manifestRef.update(m => m.copy(hashes = m.hashes + hash))
        } yield ()
      }
    } yield ()

  def doProcessing(bytes: Array[Byte]): IO[Unit] =
    IO.println(s"Processing ${bytes.length} bytes...")

  def run: IO[Unit] = {
    val files = List("/data/file1.csv", "/data/file2.csv")
    
    Ref.of[IO, ProcessedManifest](ProcessedManifest(Set.empty)).flatMap { manifestRef =>
      files.traverse_(file => processFile(file, manifestRef))
    }
  }
}
```

**Key points**:
- SHA-256 digest as idempotency key.
- Manifest (in-memory here; persist to DB/file in production).
- Safe to re-run; duplicate hashes skipped.

#### Logging best practices example

```typescript
import pino from "pino";

const logger = pino({
  redact: {
    paths: [
      "req.headers.authorization",
      "req.body.password",
      "req.body.ssn",
      "req.body.credit_card",
      "*.email"  // Redact all email fields
    ],
    censor: "[REDACTED]"
  },
  level: process.env.LOG_LEVEL || "info"
});

function logIncomingFile(fileName: string, checksum: string, recordCount: number) {
  logger.info({
    event: "file_received",
    file_name: fileName,
    checksum,
    record_count: recordCount,
    partner: "acme_corp",
    received_at: new Date().toISOString()
  }, "File received for processing");
}

function logError(err: Error, context: Record<string, any>) {
  logger.error({
    event: "processing_error",
    error: err.message,
    stack: err.stack,
    ...context
  }, "Processing failed");
}

// Usage
logIncomingFile("customers_2025-11-05.csv", "abc123...", 1024);
logError(new Error("Invalid schema"), { file_name: "bad.csv", row: 42 });
```

**Key points**:
- Automatic PII redaction via path specs.
- Structured fields for easy querying.
- No raw payload dumps; only metadata.

![Observability Stack](images/observability.png)

- **Metrics**: counts, rates, latencies.
- **Logs**: structured JSON logs for easy search.
- **Traces**: end-to-end timing and context across services using [OpenTelemetry](https://opentelemetry.io/).

**Learn more**: [OpenTelemetry docs](https://opentelemetry.io/docs/), [Prometheus](https://prometheus.io/), [Grafana](https://grafana.com/), [Google Cloud Logging redaction](https://cloud.google.com/logging/docs/redaction), [Stripe Idempotency Keys](https://stripe.com/docs/idempotency), [RFC 8297 pagination guidance](https://www.rfc-editor.org/rfc/rfc8297).

---

## Security and governance

### Integration security best practices (deep dive)

Defense-in-depth for data integrations means layering controls across identity, transport, data, runtime, and operations. Below is a concise, actionable checklist with definitions.

Identity and access management (IAM)
- Least privilege (grant only the minimal permissions needed) for service accounts; separate read vs write roles per source/sink.
- Short-lived credentials (secrets that expire quickly) via OIDC (OpenID Connect: identity layer on top of OAuth 2.0) or STS (Security Token Service) where supported.
- Rotate keys (change them regularly) and enforce MFA (multi-factor authentication) for human access; disable password auth for SFTP/SSH.
- Use workload identity (binding an app’s identity to its runtime, e.g., Kubernetes ServiceAccount to cloud IAM) to avoid static keys.

Secrets management
- Store secrets in a vault (specialized secure storage) like HashiCorp Vault or a cloud secrets manager; never in code or config files.
- Use envelope encryption (secrets encrypted with a data key, which is encrypted by a master key) and audit reads of secrets.
- Inject secrets at runtime via environment variables or files with least privilege; avoid printing secrets in logs.

Network and transport
- Enforce TLS (Transport Layer Security) for all HTTP/gRPC; pin certificates (validate the server’s certificate or CA bundle).
- Mutual TLS (mTLS: both client and server present certificates) for sensitive partner links or internal services.
- Private connectivity (VPC peering, PrivateLink-style) where possible; restrict egress (outbound network) to allowlisted hosts.
- IP allowlists for SFTP/SSH and webhook sources; rate-limit endpoints to mitigate abuse.

Data at rest and in use
- Encrypt at rest (disk/database encryption) using managed KMS (Key Management Service) keys with rotation.
- Field-level protection for PII (masking, tokenization, or format-preserving encryption) in logs, staging, and warehouses.
- Minimize data collection (data minimization) and retain only as long as needed (retention policies).
- Hashing for idempotency (e.g., SHA-256) should not reuse raw PII as salts (random inputs to hashing); use constant-time comparisons where appropriate.

Application layer and inputs
- Validate inputs at the edge with schemas; reject on failure and quarantine samples for debugging.
- Canonicalize file formats (normalize newlines, encodings) to avoid parser evasion.
- For webhooks, verify signatures (HMAC: hash-based message authentication) and timestamps; replay-protect with idempotency keys.
- For EDI, verify control numbers and envelopes; require 997/999 acknowledgments.

Runtime hardening
- Run containers as non-root; use read-only root filesystems; drop Linux capabilities not needed.
- Apply seccomp/AppArmor (Linux kernel sandboxing) or equivalent; keep images minimal and scanned for CVEs (known vulnerabilities).
- Use policy agents (e.g., OPA: Open Policy Agent) for admission controls and data egress rules.

Observability and detection
- Structured audit logs (who did what, when, where) for data reads/writes, schema changes, and policy decisions.
- Security telemetry (metrics and traces) for auth failures, signature mismatches, schema drift, and unusual data volumes.
- Alerts with runbooks (clear steps to respond) and automatic quarantine on repeated failures.

Compliance and governance
- Data classification (tag by sensitivity: public/internal/confidential/restricted) drives masking and access policies.
- DSRs (Data Subject Requests) support: track data lineage to fulfill deletion/access requests (GDPR/CCPA).
- DPIAs (Data Protection Impact Assessments) for high-risk integrations; document residual risks and mitigations.

Partner and third-party risk
- Contractual SLAs (service level agreements) for timeliness, availability, and schema change notice.
- Security addenda (controls, breach notification windows), SOC 2/ISO 27001 reports, and penetration testing attestations.
- Onboarding/offboarding checklists: access provisioning, test file exchange, key rotation schedule, emergency contacts.

Change management and break-glass
- Blue/green or canary deployments (release to a subset first) for adapters; rollback automation.
- Break-glass access (emergency elevated access) with strong approvals, time limits, and full audit.
- Versioned data contracts with backward compatibility checks in CI.

#### Security layers diagram

![Security defense in depth](images/security-defense.png)

#### Practical examples: webhook signature verification

Always verify webhook signatures before processing to ensure authenticity (message came from the claimed sender) and integrity (message was not tampered with).

##### TypeScript: HMAC webhook verification

```typescript
import * as crypto from "node:crypto";
import { Request, Response } from "express";

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET!;
const MAX_AGE_SECONDS = 300; // 5 minutes

function verifyWebhook(req: Request): boolean {
  const signature = req.headers["x-webhook-signature"] as string;
  const timestamp = req.headers["x-webhook-timestamp"] as string;
  
  if (!signature || !timestamp) {
    return false;
  }
  
  // Replay protection: reject old messages
  const age = Date.now() / 1000 - parseInt(timestamp, 10);
  if (Math.abs(age) > MAX_AGE_SECONDS) {
    console.warn("Webhook too old or future-dated");
    return false;
  }
  
  // Compute expected signature
  const payload = timestamp + "." + JSON.stringify(req.body);
  const expected = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(payload, "utf8")
    .digest("hex");
  
  // Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(signature, "hex"),
    Buffer.from(expected, "hex")
  );
}

export function handleWebhook(req: Request, res: Response) {
  if (!verifyWebhook(req)) {
    res.status(401).send("Unauthorized");
    return;
  }
  
  // Process webhook payload
  console.log("Valid webhook:", req.body);
  res.status(200).send("OK");
}
```

**Security properties**:
- HMAC prevents tampering and proves sender knows the secret.
- Timestamp + age check prevents replay attacks.
- `timingSafeEqual` prevents timing side-channels.

##### Python: webhook signature with constant-time compare

```python
import hashlib
import hmac
import time
from flask import Flask, request, abort

WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode("utf8")
MAX_AGE_SECONDS = 300

app = Flask(__name__)

def verify_webhook(request) -> bool:
    signature = request.headers.get("X-Webhook-Signature")
    timestamp = request.headers.get("X-Webhook-Timestamp")
    
    if not signature or not timestamp:
        return False
    
    # Replay protection
    age = abs(time.time() - int(timestamp))
    if age > MAX_AGE_SECONDS:
        print("Webhook too old")
        return False
    
    # Compute expected signature
    payload = f"{timestamp}.{request.get_data(as_text=True)}"
    expected = hmac.new(
        WEBHOOK_SECRET,
        payload.encode("utf8"),
        hashlib.sha256
    ).hexdigest()
    
    # Constant-time comparison
    return hmac.compare_digest(signature, expected)

@app.route("/webhook", methods=["POST"])
def handle_webhook():
    if not verify_webhook(request):
        abort(401, "Unauthorized")
    
    # Process webhook
    print("Valid webhook:", request.json)
    return "OK", 200
```

**Security properties**:
- `hmac.compare_digest` is constant-time and safe against timing attacks.
- Age check defends against replay.
- Signature covers both timestamp and body.

##### Scala: HMAC verification with cats-effect

```scala
import cats.effect.IO
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import scala.concurrent.duration._

object WebhookVerifier {
  val secret: Array[Byte] = sys.env("WEBHOOK_SECRET").getBytes("UTF-8")
  val maxAge: FiniteDuration = 5.minutes

  def verifySignature(signature: String, timestamp: Long, body: String): IO[Boolean] = IO {
    val age = Math.abs(System.currentTimeMillis() / 1000 - timestamp)
    if (age > maxAge.toSeconds) {
      return IO.pure(false)
    }

    val payload = s"$timestamp.$body"
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(secret, "HmacSHA256"))
    val expected = mac.doFinal(payload.getBytes("UTF-8"))
      .map("%02x".format(_))
      .mkString

    // Constant-time compare
    MessageDigest.isEqual(signature.getBytes, expected.getBytes)
  }

  def handleWebhook(signature: String, timestamp: Long, body: String): IO[Unit] =
    verifySignature(signature, timestamp, body).flatMap {
      case true => IO.println(s"Valid webhook: $body")
      case false => IO.raiseError(new Exception("Unauthorized"))
    }
}
```

**Security properties**:
- `MessageDigest.isEqual` is constant-time in the JVM.
- Covers timestamp and body.
- Age check prevents replay.

#### Additional hardening patterns

- **API key rotation**: issue time-limited keys; revoke on compromise; store hashes, not plaintext.
- **Certificate pinning**: hardcode or allowlist expected CA/cert fingerprints; reject mismatches.
- **Egress filtering**: use a proxy or firewall to allow only known destination IPs/domains.
- **Data loss prevention (DLP)**: scan outbound data for patterns (SSNs, credit cards) and block or alert.
- **Tokenization**: replace sensitive fields with tokens; store mapping in a secure vault; detokenize only where needed.
- **Immutable audit trail**: write-once logs to object storage with legal holds; hash chain for tamper-evidence.

**Learn more**: [OWASP API Security Top 10](https://owasp.org/www-project-api-security/), [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework), [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/).

![Security layers and secrets management](images/security.png)

- **Least privilege**: minimal roles and permissions.
- **Secrets management**: store API keys in a vault service ([HashiCorp Vault](https://www.vaultproject.io/), [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/), [1Password](https://1password.com/)).
- **Encryption**: at rest and in transit.
- **PII handling**: mask or tokenize sensitive fields where possible.

**Learn more**: [OWASP top 10](https://owasp.org/www-project-top-ten/), [GDPR compliance](https://gdpr.eu/).

---

## Pros and cons quick reference

### Batch

- **Pros**: simpler, cheaper.
- **Cons**: higher latency, backfills can be heavy.

### Streaming

- **Pros**: low latency, incremental updates.
- **Cons**: more components to operate.

### ETL

- **Pros**: curated data at destination.
- **Cons**: less raw history, less flexibility later.

### ELT

- **Pros**: flexible, audit-friendly, reversible.
- **Cons**: relies on downstream compute and governance.

### CDC

- **Pros**: fresh data without full scans.
- **Cons**: requires log access and careful schema changes.

---

## Curated learn-more links

### Data contracts and schemas

- [JSON Schema](https://json-schema.org/)
- [OpenAPI](https://www.openapis.org/)
- [Protocol Buffers](https://protobuf.dev/)

### Orchestration

- [Dagster docs](https://dagster.io/)
- [Prefect docs](https://www.prefect.io/)
- [Temporal docs](https://temporal.io/)

### Transformations

- [dbt Core docs](https://docs.getdbt.com/)
- [Spark docs](https://spark.apache.org/docs/latest/)

### Streaming

- [Kafka docs](https://kafka.apache.org/documentation/)
- [Redpanda docs](https://docs.redpanda.com/)
- [Kafka Connect](https://docs.confluent.io/platform/current/connect/index.html)
- [Debezium](https://debezium.io/)

### Validation

- [Zod](https://zod.dev/)
- [Pydantic](https://docs.pydantic.dev/)
- [Circe](https://circe.github.io/circe/)

### Observability

- [OpenTelemetry docs](https://opentelemetry.io/docs/)

### Data quality

- [Great Expectations](https://greatexpectations.io/)
- [Soda Core](https://www.soda.io/)

### Lakehouse table formats

- [Apache Iceberg](https://iceberg.apache.org/)
- [Delta Lake](https://delta.io/)
- [Apache Hudi](https://hudi.apache.org/)

---

## Open-source component choices (OSS)

Use proven OSS components per layer. Pick one per layer first; add complexity only when needed.

![OSS architecture](images/oss-architecture.png)

Event backbone
- Redpanda (Kafka-compatible log; single-binary, low ops) — Pros: fast, simple ops; Cons: smaller ecosystem than Kafka.
- AutoMQ (Kafka API on S3 with tiered storage) — Pros: cost-efficient at scale; Cons: S3 latency, newer project.
- Kafka (Apache) — Pros: mature ecosystem; Cons: heavier ops.

Connectors and CDC
- Airbyte (ELT connectors) — Pros: many sources/sinks, OSS; Cons: connector quality varies; pin versions and test.
- Kafka Connect + Debezium (CDC) — Pros: robust CDC; Cons: runs on Kafka stack.

Schema registry
- Apicurio or Confluent Schema Registry — manage Avro/Protobuf/JSON schemas; enforce compatibility (backward/forward/full).

Transformation
- dbt Core (SQL models) — Pros: analytics-friendly; Cons: SQL-only.
- Spark/Flink — Pros: heavy/streaming compute; Cons: ops complexity.

Orchestration
- Dagster/Prefect — Pros: developer-friendly; Cons: scaling needs tuning.
- Temporal — Pros: durable, code-first workflows; Cons: steeper learning curve.

Catalog & lineage
- DataHub/Amundsen (catalog), OpenLineage + Marquez (lineage) — discoverability and end-to-end tracking.

Quality
- Great Expectations/Soda — expectations and data quality checks.

Access/serving
- PostgREST/Hasura/GraphQL or REST microservices; Reverse ETL for SaaS syncs.

---

## Schema governance and registries

![Schema governance flow](images/schema-governance.png)

Compatibility modes
- Backward-compatible (new producer works with old consumers) for events; Full compatibility for critical payloads.
- Subject naming strategy: topic-name + record-name; version every change; deprecate fields, don’t delete.

Policies
- Disallow breaking changes in CI; require owners/approvers per schema; maintain changelog and samples.
- Add semantic versioning to payloads; include `schema_version` in messages/files.

Validation
- Validate at ingress against the active registry version; log schema drift with alerts.

---

## Table design and storage (warehouse/lakehouse)

![Table design and maintenance](images/table-design.png)

Formats & compression
- Prefer Parquet (columnar) with Snappy/ZSTD.

Partitioning & sorting
- Partition by event_date/ingest_date and tenant/entity; sort by id/updated_at for fast merges.

Small files & compaction
- Schedule compaction; aim for 128–1024MB files; vacuum old snapshots.

ACID tables
- Use Iceberg/Delta/Hudi for ACID, time travel, and merge/upsert support.

Retention & GDPR
- Implement per-table retention; support deletions with row-level deletes and metadata compaction.

---

## Error handling, DLQs, and replay

Error taxonomy
- Distinguish transient (retryable), permanent (validation), and systemic (downstream outage) errors.

Dead-letter queues (DLQ)
- Route permanent failures (with context and sample payload) to DLQ; set retention and access controls.

Replay
- Provide tooling to replay from DLQ/landing zones; ensure idempotent sinks; record replay provenance.

Mermaid: DLQ and replay
![DLQ and replay](images/dlq-replay.png)

---

## Environments, CI/CD, and promotion

![CI/CD promotion and gates](images/ci-cd.png)

- IaC (Terraform, Helm) for infra; GitOps for deployments.
- Separate dev/test/staging/prod with distinct secrets and data stores; forbid production data in lower envs.
- Promotion gates: tests (unit/integ/e2e), schema checks, security scans; change approvals for partner-facing flows.
- Config per env: endpoints, keys, cut-offs; no code changes for env differences.

---

## Privacy in lower environments

- Use synthetic or masked data; maintain referential integrity in masked datasets.
- Redact PII in logs and traces; block secrets/PII from leaving prod.
- Provide data generation scripts for realistic test coverage.

---

## Operational resilience (HA/DR)

![HA/DR multi-region](images/ha-dr.png)

- Define RPO (recovery point) and RTO (recovery time); test disaster recovery regularly.
- Multi-AZ/region for event backbone and stores; replication for catalogs and schema registries.
- Back up configs, schemas, manifests; practice restore drills.

---

## SLIs/SLOs and alerting

![SLOs and alerting](images/slos.png)

- SLIs: data freshness, on-time delivery %, processing latency p95, error rate, DLQ rate, schema drift rate.
- SLOs: e.g., 99% files processed within 15 minutes of arrival; <0.1% validation failures per day.
- Alerts: page on SLO burn; ticket on chronic drift; dashboards for partner scorecards.

---

## Connector lifecycle and governance

![Connector lifecycle](images/connector-lifecycle.png)

- Pin connector versions (Airbyte/Kafka Connect); stage upgrades in lower env; run contract tests with samples.
- Maintain per-connector runbooks (contact, SLAs, formats, auth, cutoffs); schedule key rotations.

---

## Next steps

1. Start with a small pipeline using batch ELT, schemas, and idempotent writes.
2. Add tests and observability from the beginning.
3. Move to CDC or streaming if freshness requirements demand it.

---

## Notes for contributors

- Keep definitions inline as terms first appear.
- Keep examples short and runnable where possible.
- Maintain an FP-first style: pure core logic, effectful edges, composition.
