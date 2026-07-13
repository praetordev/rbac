Before Story 1, we're doing one small slice: a structured decision accessor.
This addresses the seam the pinning step exposed — Decision has no public
"who decided and how" surface, so the characterization tests currently either
read the unexported trace field or pin strategy-dependent Reason prose. Both
are pinning the wrong thing.

Do this in strict order — do NOT collapse it into one pass:

1. DOWNGRADE the two awkward assertions first, WITHOUT adding the accessor yet.
   - TestCharacterizationStrategyDivergence and the verdict table must assert
     only the real event: (allow, deciding-rule, effect). No verbatim Reason
     prose. Stop asserting "allowed by exact-global" / "ALLOW by ..." etc.
   - At this stage the deciding rule is still identified by Name (no id exists
     yet) — extracting it may be ugly, that's fine. The point is to pin
     behavior, not rendering.
2. CONFIRM GREEN. The net now asserts behavior at the current implementation,
   still passing. This is the honest baseline.
3. THEN build the accessor:
   - A typed Decider() (or equivalent) on Decision returning deciding rule
     identity + effect.
   - Key the deciding rule on a STABLE RULE ID, not the human-facing Name.
     Names can collide, and the current findRule helper silently takes the
     first match on Name — that's a latent correctness bug in the test. Give
     rules a stable identifier and have Decider() return that, so "which rule
     decided" is unambiguous. If rules have no id today, add a minimal one.
   - Derive Reason from ONE consistent place, so deny-overrides, first-match,
     and default-deny stop rendering the same event three different ways.
   - Migrate the two tests onto this surface: switch the deciding-rule
     assertion from Name to the stable id, and remove the unexported-field
     reach and the string-matching findRule helper.
4. CONFIRM GREEN AGAIN. If the asserted (allow, deciding-rule, effect) triple is
   unchanged, the accessor was a pure shape change and no decision moved. That
   green is the proof the refactor was safe.

   NOTE on the identifier switch: between step 1 and step 3, HOW the deciding
   rule is referenced changes (Name -> stable id). That is expected and is NOT a
   behavior change — it's the same rule deciding, referred to a more robust way.
   Only treat it as a real change if WHICH rule decides, the allow, or the
   effect differ. A red test that's purely about the Name->id representation is
   fine and explained.

Scope limits:
- This is the accessor + stable rule id + consistent Reason derivation ONLY.
- Do NOT build trace disclosure levels (full-to-logs vs minimal-to-user). That
  stays in Story 5 — it's a new capability with its own design, and it isn't
  blocking anything here.
- Do not touch the parser, snapshots, or any other surface.

The whole reason for the downgrade-then-build ordering: it keeps the net able to
distinguish "a decision changed" from "the prose rendered differently." If you
do the accessor and the assertion change in one pass, that diagnostic is lost.
Keep them as separate green checkpoints.