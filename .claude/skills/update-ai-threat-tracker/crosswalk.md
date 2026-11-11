# Actor-naming & TTP crosswalk

Used in Stage 3 to (a) reconcile a newly-reported actor to an existing tracker row via AKAs, and
(b) validate that each TTP label maps to a real framework ID — **MITRE ATT&CK** for Category A,
**MITRE ATLAS** for Category B. Seeded from the `TRACKER.md` AKAs column + the cybershujin origin repo.
**Extend this file whenever a new AKA or label appears.**

## Actor AKA crosswalk (reconcile before proposing a "new" row)

| Canonical / tracker name | MITRE ATT&CK Group | Microsoft "weather" | Google/Mandiant | CrowdStrike | Other AKAs |
| --- | --- | --- | --- | --- | --- |
| APT28 / Fancy Bear | G0007 APT28 | Forest Blizzard | FROZENLAKE | Fancy Bear | Sofacy, Sednit, STRONTIUM, Pawn Storm, Unit 26165; malware PROMPTSTEAL/LameHug |
| APT29 / Cozy Bear | G0016 APT29 | Midnight Blizzard | — | Cozy Bear | NOBELIUM, The Dukes |
| APT31 | G0128 APT31 | Violet Typhoon | — | Judgment Panda | Zirconium |
| APT41 | G0096 APT41 | Brass/other | — | Wicked Panda | BARIUM, Winnti, Double Dragon |
| APT42 | G1044 APT42 | Mint Sandstorm | — | Charming Kitten | TA453, Yellow Garuda |
| APT43 / Kimsuky | G0094 Kimsuky | Emerald Sleet | — | Velvet Chollima | TA406, Thallium, THALLIUM |
| APT45 | — | Onyx Sleet | APT45 | Silent Chollima | Andariel, Stonefly (DPRK) |
| TEMP.Zagros / MuddyWater | G0069 MuddyWater | Mango Sandstorm | MUDDYCOAST | Static Kitten | Seedworm, TEMP.Zagros |
| Salt Typhoon | — | Salt Typhoon | — | — | GhostEmperor, FamousSparrow, Earth Estries, UNC2286 |
| Aquatic Panda | G0143 Aquatic Panda | Charcoal Typhoon | — | Aquatic Panda | ControlX, RedHotel, Bronze University |
| Sodium | — | Salmon Typhoon | — | Maverick Panda | APT4, Samurai Panda |
| Imperial Kitten | — | Crimson Sandstorm | — | Imperial Kitten | Yellowliderc, Tortoiseshell |
| Scattered Spider | G1015 Scattered Spider | Storm-0875 / Octo Tempest | UNC3944 | Scattered Spider | Muddled Libra |
| Indrik Spider | G0119 Indrik Spider | — | — | Indrik Spider | Evil Corp |
| APT27 | G0027 Emissary Panda | — | — | — | Iron Tiger, LuckyMouse, Budworm, Bronze Union |
| UNC1069 | — | — | UNC1069 (MASAN) | — | CryptoCore (DPRK; BlueNoroff-adjacent), MIDNIGHT NEPTUNE |
| UNC4899 | — | — | UNC4899 (PUKCHONG) | — | (DPRK; TraderTraitor/Lazarus cluster) |
| UNC2970 | — | — | UNC2970 | — | (DPRK; Operation Dream Job) |
| DPRK IT-worker op | — | Jasper Sleet / Storm-1877 | — | FAMOUS CHOLLIMA | Wagemole, Nickel Tapestry, "Sapphire Sleet" (adjacent) |
| Bitter APT | G1002 Bitter | — | — | — | APT-C-08, Aramanberry |
| TA547 | — | — | — | Scully Spider | — |

> Anthropic uses opaque `GTG-####` codes (GTG-1002, GTG-2002, GTG-5004) and only sometimes maps them to public
> clusters (e.g. GTG-1002 = a Chinese state group). Track by the GTG code until a public mapping is published.
> GTIG/Mandiant `UNC####` are un-graduated clusters; keep the UNC designation until Mandiant graduates it to APT##.

## Category A — LLM-themed TTP label → MITRE ATT&CK ID (validate every run)

**Microsoft-seeded (in Appendix A):**
- LLM-informed reconnaissance → T1592 / T1593 / T1590 / T1591 / T1589
- LLM-enhanced scripting techniques → T1588 (Develop Capabilities: Tool) / T1059
- LLM-aided development → T1587 (Develop Capabilities) / T1587.001 (Malware)
- LLM-supported social engineering → T1566 (Phishing) / T1585 (Establish Accounts)
- LLM-assisted vulnerability research → T1588.006 (Obtain Capabilities: Vulnerabilities) / T1587.004 (Exploits)
- LLM-optimized payload crafting → T1027 (Obfuscated Files/Information)
- LLM-enhanced anomaly detection evasion → T1562.001 (Impair Defenses)
- LLM-directed security feature bypass → (2FA/CAPTCHA bypass; no single ATT&CK ID)
- LLM-advised resource development → T1587 / T1583 / T1585

**Rachel James additions (in Appendix A):**
- Lookalike LLM → T1583 (Acquire Infrastructure)
- LL Models used for backdoor deployment → T1195.001 (Supply Chain Compromise) / T1059
- DeepFake for Impersonation → T1656 (Impersonation)
- LLM-directed Automated Collection → T1114 (Email Collection) / T1119 (Automated Collection)
- LLM-enhanced data manipulation → T1565 (Data Manipulation) / T1657 (Financial Theft)
- **LLM-orchestrated operations (Agentic AI attack orchestration)** → TA0002 Execution / full kill-chain
- **LLM-embedded malware (runtime generation)** → T1059 (Command and Scripting Interpreter)
- **LLM-enhanced extortion/negotiation** → T1657 (Financial Theft)
- **AI-generated attack infrastructure (app-builder abuse)** → T1583.001 / T1608 (Stage Capabilities)

> Validation rule: every `T####[.###]` proposed in a Category A row must appear in MITRE ATT&CK Enterprise (or
> Mobile for Android cases, e.g. T1636). If a behavior has no clean ID, describe it in words and (if recurring)
> propose a new Appendix A label with credit "CREDIT: Rachel James based on <report>".

## Category B — behavior → MITRE ATLAS ID (validate every run against atlas.mitre.org)

ATLAS is the framework for **attacks on AI systems**. IDs are `AML.T####[.###]`. The list below is a SEED —
ATLAS evolves, so **confirm the current ID + name at https://atlas.mitre.org/techniques before committing a
row**, exactly as Category A validates against ATT&CK. If a behavior has no clean ATLAS ID, describe it in
words and flag it for the maintainer (ATLAS may have added/renamed a technique).

- Prompt injection (direct) → AML.T0051.000 (LLM Prompt Injection: Direct)
- Prompt injection (indirect, via docs/web/email/RAG) → AML.T0051.001 (LLM Prompt Injection: Indirect)
- Jailbreak of a deployed model for abuse → AML.T0054 (LLM Jailbreak)
- Poison training data → AML.T0020 (Poison Training Data)
- RAG / retrieval-corpus poisoning → AML.T0070 (RAG Poisoning)  *(verify — recent addition)*
- Backdoored / trojanized model → AML.T0018 (Backdoor ML Model: Poison / Inject Payload)
- ML supply-chain compromise (model/data/software/hardware) → AML.T0010 (ML Supply Chain Compromise; e.g. .003 Model)
- Exfiltration via inference API → AML.T0024 (Exfiltration via ML Inference API)
- LLM data leakage / sensitive-data disclosure → AML.T0057 (LLM Data Leakage)
- LLM plugin / tool / agent-action compromise → AML.T0053 (LLM Plugin Compromise)
- Erode model integrity (degrade/manipulate outputs) → AML.T0031 (Erode ML Model Integrity)
- Denial of ML service → AML.T0029 (Denial of ML Service)
- Downstream real-world harm from the above → AML.T0048 (External Harms; e.g. .000 Financial)
- Inference-API access as a foothold → AML.T0040 (ML Model Inference API Access)

> Validation rule: every `AML.T####[.###]` proposed in a Category B row must appear in the live ATLAS matrix.
> An A+B incident (an actor that USES AI to ATTACK another AI system) carries both an ATT&CK and an ATLAS ID.
