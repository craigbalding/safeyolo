# Plan work with GitHub issues

This guide explains how SafeYolo plans work that spans several issues. It
applies to releases and other large efforts. It also applies when an agent
factory helps with the work.

## Why we use this approach

A long checklist can show which requirements passed. It does not show how much
work remains. One unchecked item might need a short test. Another might need a
new implementation, a physical host, and independent review. Long notes inside
checklist items also make the requirement hard to find.

We use GitHub relationships and a small set of estimates to show the work.
The issue still states what must be true. Evidence still decides whether a
requirement passed. An estimate does not replace either one.

The unit of planning is an outcome that still needs acceptance. Do not count
boxes or pull requests as equal units of work. A parent issue can contain
several outcomes. A small test and a hard proof can each occupy one checkbox
but need very different effort. Size the work that remains, including its
proof and review.

## Keep each fact in one place

| Question | Record to use |
|---|---|
| What must the product do? | The relevant issue body and material discussion. |
| What proof is still missing? | The unchecked requirement and its short exception note in the issue body. |
| What passed, on which revision, and how? | The independent acceptance receipt in an issue or pull request comment. |
| Which issue is part of a larger effort? | A GitHub parent and sub-issue relationship. |
| Which issue needs another issue to finish? | A GitHub issue dependency. |
| Which task is active in a factory? | The factory supervisor checkpoint and its work handoffs. |
| What is the release order? | The release plan, issue dependencies, and current operator direction. |
| How large or uncertain is the remaining work? | The planning estimate in the GitHub Project. |

The Project is a view of the work. It is not a second assignment queue or an
acceptance record. If a Project field conflicts with an issue or a factory
checkpoint, correct the field. Do not change the evidence to match the field.
GitHub holds the durable plan for coding work: outcomes, dependencies,
estimates, and acceptance evidence. A factory keeps only the live execution
facts needed to prevent duplicate work and resume safely: current handoffs,
their owners, exact candidate revisions, and cursors. A factory working from
another system uses that system for the durable plan instead.

## Write issues that can be checked

State the outcome before the proposed implementation. Give each acceptance
requirement a clear pass condition. Name the platform or environment when it
matters. Keep a requirement unchecked until an independent reviewer accepts
the required proof.

If a test proves only part of a requirement, leave its box unchecked. Add one
short sentence in brackets after that requirement. Say what passed and what
remains. Put commands, results, candidate revisions, and detailed findings in
the acceptance receipt, then link to that receipt. Do not erase useful earlier
evidence when a later candidate changes.

Close an issue only after all its required outcomes have independent acceptance
or an explicit operator decision removes a requirement. A merged pull request
can be a useful increment without closing its issue. Keep the pull request,
accepted commit, and merge commit linked to the issue.

## Use the right GitHub relationship

Make an existing issue a sub-issue when it is a distinct part of a larger
outcome. Create a new sub-issue when the work can be assigned, reviewed, blocked,
or completed on its own and the parent issue is too broad to show that result.
The sub-issue must name its own outcome and proof. Do not create one issue for
every checkbox by default. Keep a small requirement in its current issue when
it has the same owner, candidate, and acceptance path as nearby requirements.

For a large issue, the parent should keep the overall acceptance contract.
Each child represents an outcome the factory can assign, review, and close
independently.
Show the children as cards on the Project board so they move through the status
columns. GitHub then shows sub-issue progress on the parent. Close the parent
only when its own complete acceptance contract is proved.

For example, [#637](https://github.com/craigbalding/safeyolo/issues/637) can
keep the cross-platform installed-proxy contract while separate children prove
an installed Linux guest lifecycle and physical-Mac VZ isolation. Those proofs
use different environments and can finish separately. In
[#638](https://github.com/craigbalding/safeyolo/issues/638), one child could
cover the durable task-policy writer repair while another covers the full
Python→Rust→Python rollback run. The parent still requires the complete state
round-trip. In [#621](https://github.com/craigbalding/safeyolo/issues/621),
the shared test selector can be accepted before the final post-deletion run.
Keep those outcomes separate so #621 and #640 do not become whole-issue
prerequisites of each other.

Use an issue dependency when completing one issue requires another issue to
finish. A dependency describes a real prerequisite, not a preferred work
order. If only one test needs an earlier result, state that narrower condition
in the test requirement. Avoid marking the whole issue blocked without cause.

GitHub provides [sub-issues](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/adding-sub-issues)
and [issue dependencies](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/creating-issue-dependencies).
Use those relationships instead of copying a list of issue numbers into each
issue body. A release plan may still explain the reason for an order.

## Estimate remaining work

For a multi-issue effort, use one GitHub Project owned by the repository owner
or team. Add the parent issue and its actionable sub-issues. Size each issue
once. The parent gives the overview; do not add the size of the parent to the
size of its children. Use these planning fields when the Project supports them:

| Field | Values | Meaning |
|---|---|---|
| Size | S, M, L, XL | Expected work still needed to implement, prove, review, and integrate the issue. |
| Uncertainty | Low, Medium, High | Chance that the current plan misses work or that proof will be difficult to obtain. |
| Release phase | Named phases for that effort | Where the issue belongs in the release sequence. |
| Status | Ready, Active, Review, Blocked, Accepted, Integrated | A short view of the current issue and factory state. |

**Ready** means the remaining outcome can be assigned. **Active** means its
implementation or proof is assigned. **Review** means an exact candidate is
awaiting independent disposition. **Blocked** means a named prerequisite stops
the remaining outcome. **Accepted** means every required outcome passed
independent review and awaits integration. **Integrated** means the accepted
result reached the release branch. A partly accepted issue follows the state
of its remaining work; accepted increments do not make the whole issue
Accepted.

Size is relative, not a promise of hours. Use **S** for one bounded change or
proof with known tools. Use **M** for several related steps or one unfamiliar
boundary. Use **L** for work across components, platforms, or substantial
acceptance evidence. Use **XL** when the issue is too broad for a useful single
estimate; first consider a small number of independent sub-issues. A short but
hard-to-prove security case may be L. A long routine edit may be M.

Set uncertainty separately. Use **Low** when the path and proof are known.
Use **Medium** when one material dependency or test result is unknown. Use
**High** when a required environment, behavior, or acceptance method remains
unproved. State the reason in the issue or a planning comment. Revisit size and
uncertainty when evidence changes. Do not treat an estimate as proof that work
is ready to start.

The release coordinator updates Project fields from the current issue, pull
request, and factory records. **Accepted** means independent review passed the
required outcome. **Integrated** means the accepted change reached the release
branch. A status change alone proves neither event. If a partly accepted issue
still has required work, show the status of the remaining work and keep its
acceptance boxes accurate.

Use [Project fields and views](https://docs.github.com/en/issues/planning-and-tracking-with-projects/understanding-fields)
to show the release map, active work, blocked work, accepted work awaiting
integration, and recently completed work. Include a view of the release's
blocking path. GitHub can show parent issues and sub-issue progress in a
Project. Project views do not calculate the release's critical path for us. The
release plan must name the chain of real dependencies and explain any forecast.

## Plan the next work

1. Read the parent outcome, current issue bodies, material discussion, and
   independent acceptance receipts. Check the integration branch and open pull
   requests before calling any item unfinished.
2. Check active assignments and pending reviews. Do not assign the same work
   twice.
3. List the remaining requirements. Separate proven work, partial proof, and
   work with no proof. Preserve the exact missing exception for partial proof.
4. Add parent and dependency relationships that the evidence supports. Split
   only the work that needs an independent owner or acceptance result.
5. Estimate each remaining issue's size and uncertainty. Record the reason for
   an unusual estimate.
6. Identify the issues that control the release finish. Give ready work on
   that path priority while other workers do independent useful work.
7. Recheck the plan after an accepted change, a failed test, a new blocker, or
   a material scope change. Update GitHub before assigning dependent work.

For a forecast, show the remaining work by size and name the blockers and
uncertain cases. Use recent accepted work to inform a range only when the work
is comparable. Do not turn a count of unchecked boxes into a completion date.
If the evidence cannot support a date, say what result would make a forecast
possible.

For a large existing backlog, a planning lead makes the first full map from
the current records. The lead records the main dependency path, estimates, and
reasons for uncertain work. The release coordinator then selects work from
live evidence. The coordinator can correct the map when a test or dependency
changes. The original map is guidance, not a frozen schedule.

## Change an active plan safely

Keep the factory working while changing planning metadata when its current
assignments are clear. Before editing an issue that a worker is using, check
the live assignment and tell the coordinator which requirements will change.
Do not change a worker's target or acceptance requirement without a targeted
update. Pause new assignments only when the old and new records could cause
duplicate or wrong work. Let accepted work and in-flight reviews keep their
exact candidate identity.

Move one issue at a time. Preserve its original requirements, checked boxes,
exception notes, and links to evidence. Check the new parent, dependencies,
Project fields, and body against the old record. Do not close or retick an
issue merely because its planning shape changed.

First add relationships and Project fields without rewriting active issue
bodies. Then shorten long issue notes one issue at a time. Keep the stable
requirement in the body, the short remaining exception beside its checkbox,
and the detailed proof in linked comments. Check every moved claim and link
against the old text before saving the body.

The coordinator selects work from current issues, dependencies, the release
plan, operator direction, and the factory checkpoint. The Project helps people
see that selection. It does not direct the coordinator by itself.
