---
layout: post
title: "Adversarial ML Attack Patterns Mapped to MITRE ATLAS — A Defender's Reference"
date: 2026-05-27 09:30:00 +0800
categories: [detection-engineering, adversarial-ml, methodology]
tags: [mitre-atlas, gan, black-box-attack, substitute-model, ml-security]
---

In 2025 I published [a peer-reviewed paper](https://doi.org/10.3778/j.issn.1002-8331.2311-0227) on data-free black-box adversarial attacks against image classifiers. The paper is firmly in the offensive ML literature — it shows that with **only API-level query access** to a target model and **no access to its training data**, an attacker can train a GAN-based substitute model and use it to craft transfer adversarial examples that succeed against deployed services (Microsoft Azure included) at greater than 78% rate.

A reasonable question for any defender reading that paper is: *what would you do about it*? This post is the answer I should have included in the original work but didn't — a step-by-step mapping of the paper's attack chain onto the **[MITRE ATLAS](https://atlas.mitre.org/)** framework (v5.6.0 at time of writing), with one concrete detection idea for each step.

ATLAS is MITRE's adversarial threat-landscape catalogue for AI systems — the ATT&CK equivalent for ML. It assigns a unique `AML.TXXXX` ID to each known offensive technique against ML, and groups them under tactics like AI Model Access, AI Attack Staging, and Impact. As of v5.6.0 it contains **170 techniques across 15 tactics**. The mapping below uses the verbatim IDs.

## The five-stage attack chain

The paper describes a complete attack pipeline. Reframed in defender language:

| # | Step | What the attacker does | ATLAS technique |
|---|---|---|---|
| 1 | Probe the target | Treat the victim model as a black box; issue inference queries through its public API | [AML.T0040 — AI Model Inference API Access](https://atlas.mitre.org/techniques/AML.T0040) |
| 2 | Build a surrogate | Train a substitute model that mimics the target's decision boundary — **without using any of the target's training data** | [AML.T0005.001 — Train Proxy via Replication](https://atlas.mitre.org/techniques/AML.T0005) |
| 3 | Generate adversarial input on the surrogate | Apply FGSM / BIM / PGD against the substitute (white-box on a model that *is* the target's shadow) | [AML.T0043 — Craft Adversarial Data](https://atlas.mitre.org/techniques/AML.T0043) |
| 4 | Verify | Sanity-check that the perturbed input flips the substitute's prediction | [AML.T0042 — Verify Attack](https://atlas.mitre.org/techniques/AML.T0042) |
| 5 | Transfer to the target | Send the adversarial input to the real target's API, induce a confident misclassification | [AML.T0015 — Evade AI Model](https://atlas.mitre.org/techniques/AML.T0015) |

The paper's specific contribution is step 2 — using a **conditional GAN with label-information conditioning** to generate the substitute model's training samples directly from random noise, rather than scraping or stealing data resembling the target's training distribution. This collapses the data-acquisition prerequisite that most prior black-box attacks required, and it is the part that should worry defenders the most. The attacker no longer needs to know what your model was trained on.

## Detection idea for each step

### Step 1 — AML.T0040: AI Model Inference API Access

The attacker needs **a lot** of queries to train a useful substitute. The paper reports needing 35–60% fewer queries than DaST and MAZE — but "fewer" here is still in the *tens to hundreds of thousands* range. That volume is the defender's primary signal.

**Detection idea (operational):**

```
Alert when (queries_per_principal_per_hour > P95 baseline × 5)
AND (input_diversity > P95 baseline)
```

`input_diversity` here is the entropy of the L2-distance histogram between consecutive queries. Legitimate users (in a typical SaaS ML deployment) tend to query semantically related inputs (e.g., consecutive frames of a video, related search images). A substitute-training attacker queries a structured exploration of the input space — the diversity histogram looks **much flatter** than normal traffic.

This is exactly the signal that the paper accidentally documents in its own ablation tables: the substitute training converges faster when the attacker samples diverse points, not when they cluster around any single class. Defenders should monitor for what attackers optimize for.

### Step 2 — AML.T0005.001: Train Proxy via Replication

This step happens **entirely on the attacker's infrastructure**. There is no direct observability from the defender's side. However, two indirect signatures exist:

**Detection idea 1 (input-side):**

The paper's GAN-based sample generator produces synthetic images. These images carry detectable artifacts — for any generator, there is a **frequency-domain signature** in the high-frequency spectrum that distinguishes its output from natural images. Run a lightweight classifier (a defender-trained ResNet18 on real-vs-synthetic) over the input stream. Flag principals whose query stream is dominated by GAN-generated inputs.

```
For each principal:
    last_N_queries = circular_buffer(1024 inputs)
    p_synthetic = mean(real_vs_synthetic_classifier(last_N_queries))
    if p_synthetic > 0.6:
        alert
```

A real user's image upload stream sits at p_synthetic ≈ 0.02. An attacker training a substitute model often spikes to p_synthetic ≈ 0.7+.

**Detection idea 2 (output-side):**

Substitute training works by aligning the surrogate's decision boundary with the target's. The attacker therefore preferentially queries inputs that **straddle the decision boundary** — these inputs make the target return near-uniform softmax distributions. Track per-principal:

```
softmax_entropy_p95 = 95th percentile of entropy(model.output) over queries
```

A baseline web user has `softmax_entropy_p95` close to 0 (most queries are confidently classified). A boundary-probing attacker sees `softmax_entropy_p95` close to `log(num_classes)`.

### Step 3 — AML.T0043: Craft Adversarial Data

This step is also attacker-side, but the **outputs of this step eventually appear at your API** as step 5 queries. The crafting algorithm (FGSM / BIM / PGD) leaves specific perturbation patterns:

| Algorithm | Perturbation signature |
|---|---|
| FGSM | Single sign-of-gradient step; perturbations are ε-bounded uniformly |
| BIM | Iterated FGSM with clipping; perturbations cluster at ε boundary |
| PGD | Iterated FGSM with random restart; perturbations look "natural" but feature-flatter than untouched inputs |

**Detection idea:**

Train an adversarial-input detector (a small auxiliary network) on triplets `(clean image, FGSM perturbation, PGD perturbation)`. At inference time, run the detector in parallel with the production model. Adversarial examples crafted by FGSM/BIM/PGD against a substitute trained on the same architecture as production have a **detectable family of artifacts** even after transfer — they are not random noise; they encode gradient direction in the target's local geometry. The paper itself demonstrates 6–10 percentage-point boost in transfer attack success across CIFAR-100/10, SVHN, FMNIST, MNIST — which means there is a structural family signature, which means there is a structural family detector.

### Step 4 — AML.T0042: Verify Attack

Verification is attacker-side and produces no direct observability. Skip.

### Step 5 — AML.T0015: Evade AI Model

This is the **last** point at which the defender can catch the chain. By the time an adversarial input arrives at the target's API, the attacker has already invested days of GPU time. But there are signal-rich features at this exact point:

**Detection idea 1 — confidence-margin anomaly:**

Adversarial examples generally cause the target to produce a confident-but-wrong prediction. From the defender's side, this looks like **a sudden change in the margin distribution**:

```
margin = max(softmax) - second_max(softmax)
```

Adversarial inputs from a transfer attack often produce `margin` values in a different tail of the distribution than legitimate inputs — and **specifically, the margin tail flips: legitimate confident-correct predictions look statistically different from confident-wrong adversarial predictions on classes the legitimate user almost never reaches**. Per-class margin baselines catch this. The paper, again, accidentally documents the signal: their `Microsoft Azure 78% attack success rate` is a 78% rate of confidently-wrong predictions, *which is itself measurable from the API logs on the operator side*.

**Detection idea 2 — ensemble disagreement:**

Run the input through 2–3 architecturally diverse models (e.g., a CNN and a ViT) and measure disagreement. Adversarial examples crafted against any single model architecture **transfer imperfectly** to architecturally distant models. The paper acknowledges this in its own discussion section: their attack works best when the substitute and target share architectural family. Ensemble disagreement is exactly the inverse of that finding turned into a defender control.

**Detection idea 3 — input pre-processing:**

Apply randomized smoothing, JPEG re-compression, or bit-depth squeezing to the input before classification. These cheap transforms remove most pixel-level perturbations without affecting semantically meaningful content. A robust deployment runs both the original and the squeezed input, and alerts when their predictions disagree.

## The mapping in one table

For the defenders who scroll to this section first:

| ATLAS technique | What the paper does | Cheapest detection |
|---|---|---|
| **AML.T0040** Inference API Access | High-volume queries to target API | Per-principal rate + input-diversity P95 cap |
| **AML.T0005.001** Train Proxy via Replication | GAN-generated training samples | Real-vs-synthetic input classifier; softmax-entropy P95 monitoring |
| **AML.T0043** Craft Adversarial Data | FGSM / BIM / PGD on the substitute | Auxiliary adversarial-input detector network |
| **AML.T0042** Verify Attack | (attacker-side, no signal) | — |
| **AML.T0015** Evade AI Model | Submit transferred adversarial input | Confidence-margin distribution monitoring + ensemble disagreement + input pre-processing |
| **AML.T0031** Erode AI Model Integrity | Cumulative effect on production accuracy | Confusion-matrix drift monitoring against a held-out clean set |
| **AML.T0034** Cost Harvesting | API quota consumed on misclassifications | Cost-per-correct-prediction baseline + alert on regression |

The last two rows (T0031 and T0034) are not described in my paper as attack goals but are the **downstream business impact** of any adversarial campaign reaching production scale. Operators of paid inference APIs (think: cloud computer-vision services, content-moderation pipelines) should monitor them as KPIs anyway; if they degrade simultaneously with the upstream signals, the chain above is the likely cause.

## Why this matters for the academic literature

Most published adversarial ML papers — mine included — stop at "we achieved X% attack success on benchmark Y." That's the right scope for an algorithms paper, but it leaves a gap. The defenders who **actually deploy** these models inherit the conclusion ("you are vulnerable") without the operational playbook ("here is what to monitor on Monday"). ATLAS is the canonical place to write that playbook — every adversarial ML paper could close with a single table that maps its threat model onto ATLAS techniques and lists at least one detection idea per technique.

This post is that closing table for my paper. The same exercise applied to other recent black-box attack papers (DaST, MAZE, the Knockoff Nets line) would yield a complementary set of detection ideas. I will likely publish a survey-style follow-up that does exactly this when time permits — the inputs are the techniques' `AML.TXXXX` IDs, and the outputs are concrete monitoring queries any MLOps team can drop into their existing observability stack.

If you publish ML offense, **close with the defender's table**. It costs you an afternoon and it changes who can act on your work.

---

The paper is at [DOI: 10.3778/j.issn.1002-8331.2311-0227](https://doi.org/10.3778/j.issn.1002-8331.2311-0227). The ATLAS v5.6.0 raw data used for the technique IDs in this post lives at [`mitre-atlas/atlas-data`](https://github.com/mitre-atlas/atlas-data). The detection-engineering ruleset for N-day CVEs is at [`sigma-detection-rules`](https://github.com/1392081456/sigma-detection-rules); the same workflow applied to ML adversaries would land in a sibling repository when the auxiliary-detector models are trained and validated — that work is on the roadmap.
