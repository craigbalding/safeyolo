# Sources and enforcement

The examples are optional provider paths checked against primary documentation
on 13 November 2026. Recheck access, terms and coverage when adopting a source.
No universal reputation score or required category block is selected here.

## Maintained threat lists

The shipped `policy feeds example hagezi` uses HaGeZi's threat intelligence mini
list, its wildcard format and suffix scope. See the project's
[maintained sources and licensing](https://github.com/hagezi/dns-blocklists) and
[threat file](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini.txt).
It is a public threat-list example, not a claim that every member is malicious
or that non-members are safe. The existing feed guide describes provider
metadata, accepted snapshots, refresh, outage, stale and rollback semantics.
No account or paid subscription is required for that public path. Acquiring the
file discloses the host's source request/IP to its hosting provider. It does not
send each assessed hostname or visit list members. Hosting logs/retention remain
outside SafeYolo's guarantees. The optional StevenBlack example also includes
advertising/tracking choices; do not silently substitute it for threat-only intent.

The named check's collection-age limit bounds accepted evidence further; it
does not renew the source's retained provider/first-observation deadline.
Repeated identical responses, HTTP 304 and rollback cannot make old evidence
young. Missing/expired data selects the rule's `on_unavailable` even when a
local-list source has chosen stale retention. A hard exclusion's unavailable
fallback can govern all scoped traffic. Choose that cost explicitly.

## Passive registration evidence

The [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json) identifies
`https://rdap.verisign.com/com/v1/` for .com. The example makes an unauthenticated
GET to `/com/v1/domain/{subject}` at that fixed adopted provider. See
[Verisign's RDAP documentation](https://www.verisign.com/news-insights/registration-data-access-protocol/)
and the [RDAP response standard](https://www.rfc-editor.org/rfc/rfc9083.html#section-4.5).
Check the current [service help/terms](https://rdap.verisign.com/com/v1/help)
before adoption. There is no paid API key in this public example. Provider
availability, rate limits and retention are not SafeYolo guarantees. Rate
limiting, a redirect or non-success response remains unavailable evidence; the
check does not automatically follow RDAP links or invoke a scanner.

This lookup is passive with respect to the assessed destination. It discloses
the normalized hostname and caller network address to the registry/provider,
which may log them. It does not connect to that hostname or prove ownership,
content safety or tenant creation. Selecting `effects: passive` records that
adopted operation contract; it cannot prove a provider's internal behavior.

`rdap_registration` requires a domain object whose normalized `ldhName` equals
the exact hostname and exactly one `registration` event with a valid non-future
RFC 3339 timestamp. The runtime binds subject, inputs, check versions, collection
time and response digest. Registration is the typed timestamp finding. Provider
revision and dataset observation time remain absent when not established; the
collection freshness bound still applies.

Transfer, last-changed, certificate, first-seen, reregistration and expiry dates
cannot substitute for registration. A returned parent domain cannot establish
`tenant.hosted.example.com`'s age. A multi-label suffix such as `example.co.uk`
needs its actual registry/provider and exact object, not last-two-label guessing.
The .com example does not claim that coverage. No-match, 404, missing/ambiguous
registration, malformed data and timeout retain unknown/failure meaning and use
the explicit fallback. The 30-day comparison is an editable example; it uses
decision time, and cached evidence cannot freeze the age at collection.

A provider's registered-within-window category can be a different named finding
adapter. Preserve that category's actual window/coverage. A finite-window list
no-match does not prove an exact age or an older domain. Cloudflare's
[domain category definitions](https://developers.cloudflare.com/cloudflare-one/traffic-controls/domain-categories/)
illustrate why newly registered and newly seen are different. This recipe does
not ship a Cloudflare account, category adapter or universal first-seen source.

## Reporting source

The research helper uses [CISA's Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and its [public JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
It is a free public reporting lookup. The request discloses the catalogue access
and caller IP to CISA/its host. Filtering by topic is local and sends no topic
query. The helper cites entries but never fetches their embedded links. Catalogue
addition time does not establish vulnerability discovery or exploitation time.

## What enforces each control

| Proposed control | Evidence and actual enforcement | Limits |
|---|---|---|
| Never visit a threat-list member | Accepted managed snapshot; named hard exclusion at connect, before the assessed socket | Covers configured hostname/suffix scope, with explicit missing/stale fallback; reporting about a member remains readable |
| Advisory list plus dynamic age | Shared named evaluator; higher advisory priority wins, equal priority uses existing action order | A favorable result never overrides a hard exclusion or the ordinary network/credential guards |
| Newly registered hostname | Exact RDAP registration timestamp; shared age comparison at connect | Provider coverage, freshness, timeout and unknown fallback remain explicit; parent age is not tenant age |
| Direct IP or redirect | IP subject makes hostname checks unavailable; every redirected destination is a new gated request | The proxy does not follow redirects itself; an earlier numeric CONNECT may have used its direct-IP fallback before TLS reveals a name |
| DNS filtering | This recipe gates proxy connections using hostname evidence | It is not an operating-system DNS firewall or complete coverage for arbitrary protocols |
| Network Security Monitoring (NSM) | Existing observations can explain recorded activity | A post-response observation cannot become evidence available before connection; process/task provenance needs its actual producer |
| Geographic or TLS condition | Existing endpoint/transport visibility where supported | No geo lookup, certificate-age or later-TLS pre-connect adapter is delivered by this recipe; a parent proxy can hide origin IP |
| Download/upload control | Existing method/path, credential and content controls continue | No complete antivirus, quarantine or media workflow is added; opaque TLS does not expose HTTP content |
| Budgets and cost | Existing network budgets, check concurrency/cache/deadline and provider limits | Preview spends no live quota and does not import current quota usage or agent-run authority; no universal paid-service budget is implied |

Offline `policy evaluate` identifies records, feed provenance, rule truth,
freshness, unavailable fallback and the existing guard's resulting action.
Live audit explanations add actual collection and execution facts. Neither a
compile nor a provider's positive assessment establishes that a running policy
is active. Use the selected instance's `policy show` and observed requests.
