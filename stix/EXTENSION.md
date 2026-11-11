# STIX extension: AI-CTI scope category (A / B)

The STIX 2.1 bundle in this directory (`threat-actors-ai-stix2.1.json`) tags every relevant object
with its **AI-CTI scope category**, so a consumer can cleanly separate the two kinds of intelligence
this feed carries:

| Category | Meaning | Framework |
|---|---|---|
| **A** | Threat actors **using AI/LLMs to conduct attacks** | MITRE ATT&CK (+ a custom LLM-TTP taxonomy) |
| **B** | Threat actors **attacking AI/ML/LLM systems** | MITRE ATLAS |

There is no native STIX or MITRE taxonomy for this distinction, so it is carried as this project's own
STIX 2.1 **extension-definition**.

## How it's encoded (three consistent signals)

Every `intrusion-set`, `attack-pattern`, `report`, and `indicator` in the bundle carries:

1. **A declared top-level property** `ai_cti_category` — a list of `"A"` and/or `"B"`
   (a list because an actor/report that spans both categories is tagged `["A","B"]`).
2. **A standard `labels` value** — `owasp-genai-category-a` and/or `owasp-genai-category-b`.
   This mirror exists because some platforms drop unknown extensions on import but always keep
   standard labels — so the category survives ingest everywhere.
3. **An `extensions` reference** to the extension-definition that declares the property:

```json
"ai_cti_category": ["B"],
"labels": ["owasp-genai-category-b"],
"extensions": {
  "extension-definition--8c3aa43e-a379-598b-bac2-960894241d75": {
    "extension_type": "toplevel-property-extension"
  }
}
```

For `attack-pattern`s the category is also implicit in the `external_references` (`mitre-attack` → A,
`mitre-atlas` → B); the explicit tag makes it uniform with the other object types.

## The extension-definition

The bundle contains one `extension-definition` SDO (stable id, regenerated deterministically):

- **id:** `extension-definition--8c3aa43e-a379-598b-bac2-960894241d75`
- **name:** `OWASP GenAI AI-CTI Category`
- **extension_types:** `["toplevel-property-extension"]`
- **property:** `ai_cti_category` — list of enum `"A"` | `"B"`
- **created_by_ref:** the OWASP GenAI Security Project identity in the same bundle.

## Consuming it

**Get only Category B objects (jq):**

```bash
jq '[.objects[] | select(.ai_cti_category? and (.ai_cti_category | index("B")))]' \
  threat-actors-ai-stix2.1.json
```

**Or, using the portable label (works even if a tool stripped the extension):**

```bash
jq '[.objects[] | select((.labels // []) | index("owasp-genai-category-b"))]' \
  threat-actors-ai-stix2.1.json
```

**TAXII:** the feed is also published as separate TAXII 2.1 collections — `all`, `category-a`,
`category-b` — so a consumer can subscribe to just the category they need without client-side
filtering. (See the feed's TAXII discovery endpoint.)

## Notes

- Objects without a category tag (e.g. `malware`, `identity`, `relationship`, the SCOs) are shared
  infrastructure; filter by the tagged objects (actors/techniques/reports/indicators) and follow their
  relationships.
- `version` of this extension: **1.0.0**. Changes to the property's shape will bump this version.
