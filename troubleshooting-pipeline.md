# Troubleshooting Log: Getting the SSH Log Parser to Actually Run

**Component:** Log ingestion pipeline (Elastic Agent → Elasticsearch)
**Symptom:** Ingest pipeline was validated and correct, but never applied to real data

## Goal

Parse raw `auth.log` lines shipped by Elastic Agent into structured ECS fields
(`source.ip`, `user.name`, `event.outcome`) using an Elasticsearch ingest
pipeline with a `grok` processor, so detections and dashboards could filter
and group by attacker IP instead of scanning free text.

## Step 1 — Build and validate the pipeline

Created `victim-auth-pipeline` (grok + two conditional `script` processors to
derive `event.outcome` from `event.action`). Verified it with
`_ingest/pipeline/victim-auth-pipeline/_simulate` against both an
`Accepted password` and a `Failed password` sample line — both simulations
returned correctly parsed fields. **The pipeline itself was never the
problem.**

## Step 2 — Attempt: attach the pipeline on the shipping side

Elastic Agent (9.5.4, standalone mode, no Fleet) config exposes a `pipeline`
key. Tried it in two places, one after the other:

1. Under the filestream input's `streams[]` entry, next to `data_stream` and
   `paths`.
2. Under `outputs.default`, alongside `type` and `hosts`.

Both were accepted without any validation error — `elastic-agent status`
stayed `HEALTHY`, and `elastic-agent inspect` even echoed the `pipeline` key
back in the rendered effective config. Despite that, freshly generated SSH
login events kept arriving in Elasticsearch as flat, unparsed `message`
strings — no `source.ip`, no `user.name`, no `event.outcome`.

**Root cause:** in this Elastic Agent version/mode, a `pipeline:` key set at
either the input or the output level is silently accepted into the config
but never actually forwarded to the underlying log shipper at runtime. There
is no error message pointing at this — it just quietly does nothing, which
is what made it slow to diagnose (config looks correct, agent reports
healthy, yet behavior doesn't change).

## Step 3 — Fix: attach the pipeline on the Elasticsearch side instead

Rather than relying on the *sender* to request pipeline processing, the fix
moves the instruction to the *receiver*: Elasticsearch data streams support a
`index.default_pipeline` index setting, which applies a pipeline to every
document written into a matching index, regardless of what the client sent.

```json
PUT _index_template/victim-auth-template
{
  "index_patterns": ["logs-victim.auth-*"],
  "data_stream": {},
  "priority": 500,
  "composed_of": ["logs@mappings", "logs@settings", "ecs@mappings", "ecs@dynamic_templates"],
  "template": {
    "settings": {
      "index.default_pipeline": "victim-auth-pipeline"
    }
  }
}
```

One extra wrinkle: the `logs-victim.auth-default` data stream already existed
(created automatically the first time Elastic Agent shipped data, before this
template existed). Index templates only apply to backing indices created
*after* the template exists — an already-open data stream doesn't pick up a
new template retroactively. Forcing a rollover created a fresh backing index
that evaluated templates again and picked up the new one:

```
POST logs-victim.auth-default/_rollover/
```

Immediately after the rollover, newly ingested SSH login events came through
fully parsed (`source.ip`, `user.name`, `event.outcome`, `event.action` all
present as real fields).

## Lesson learned

When a pipeline needs to run on ingested data, prefer attaching it at the
**index/data-stream level** (`index.default_pipeline` via an index template)
over relying on shipper-side (`pipeline:`) configuration — it's enforced by
Elasticsearch itself, independent of which agent/version/mode is doing the
shipping, and it's the same mechanism used for real production log
pipelines. Remember that changing an index template never retroactively
affects an already-open data stream — a rollover is required to make a
template change take effect.
