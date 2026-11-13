# Kibana Alerts Setup

`scripts/deploy_sigma_rules.py` turns the Sigma rules into Kibana detection rules (Elastic Security). They work with the free Basic license.

## Deploy

```bash
python3 scripts/deploy_sigma_rules.py            # create or update the rules, disabled
python3 scripts/deploy_sigma_rules.py --enable   # and enable them
python3 scripts/deploy_sigma_rules.py --dry-run  # show what it would do
```

What each rule gets:

- **Query**: EQL from `macos_esf_ecs` + `macos_ul_ecs`, on `macos-telemetry-esf-*` or `macos-telemetry-ul-*`. Correlations: see below.
- **Schedule**: every 5 minutes, looking back 6 minutes. Rules alert on new events, not on history that was indexed before they ran.
- **Severity and risk score**: from the Sigma `level`. At most 100 alerts per run.
- **MITRE ATT&CK**: from the rule's ATT&CK tags; each technique is filed under its own tactics in pySigma's ATT&CK data.
- **Tags**: `macos`, `sigma`, and `esf` or `unified-logging`.
- **Rule ID**: `coresigma-<file name>` (`coresigma-ul-<file name>` for UL rules). A redeploy updates the rule with the same ID and keeps whether it's enabled.

Correlations deploy too, tagged `correlation`, on their base rules' indices:

- **`temporal_ordered`** (Paste-to-Stealer Chain, Gatekeeper Evasion Staging): an EQL rule with an EQL `sequence by <group-by> with maxspan=<timespan>`, one step per base rule in order. It alerts only when the steps happen in that order.
- **`temporal`, `event_count`, `value_count`** (the other five): an ES|QL rule, from pysigma-backend-elasticsearch's ES|QL backend. ES|QL counts in fixed `date_trunc` windows of the timespan, so a chain that crosses a window boundary is missed, and it matches plain strings case-sensitively.
- **Schedule**: every 5 minutes, looking back the timespan plus 6 minutes, so a chain that ends in a run's window is whole. An EQL sequence's alert is deduplicated across runs (Kibana derives its id from the events; on the bench, re-runs over the same chain added no alert).
- **One alert per window (ES|QL)**: an ES|QL correlation's alert has no source event, so Kibana would give it a new id, and alert again, on every run whose look-back holds the window. So each ES|QL rule ends with `| where timebucket > now() - <timespan + 360> seconds and timebucket <= now() - <timespan + 60> seconds`: a run alerts only on the windows that closed 1 to 6 minutes before it, and consecutive runs 5 minutes apart take each window once. The cost is delay: an alert can come up to timespan + 6 minutes after its window opened (36 minutes for the 30-minute Package Manager Payload to Persistence). The numbers assume the 5-minute interval: if you change a rule's interval, change the band's width (360 − 60 = 300 seconds) to match, or windows alert twice or are skipped. A run that starts late or early can skip or repeat a window; on the bench, runs started within about 20 ms of their schedule.
- **Alerts**: an EQL sequence gives one alert plus a building-block alert per step; each step's `kibana.alert.original_time` is its event's time. An ES|QL correlation's alert has no `original_time`: it carries the group-by fields, the count, and `timebucket`, the start of its fixed window.

Base rules deploy only inside their correlation, so they don't appear on their own.

## View alerts

- **Security → Alerts** lists them.
- **Security → Rules → Detection rules** shows each rule, filterable by the `sigma` tag, with its last run's status and errors.
- The **Sigma Rule Triggers Overview** dashboard in `exports/all_dashboards_latest.ndjson` charts `.alerts-security.alerts-default`.

Notifications are rule actions (edit a rule → **Actions**); which connectors you can use depends on your license.

## Troubleshooting

### A rule fails to deploy

The script prints `FAIL` with Kibana's reason. A query Elasticsearch rejects at run time shows as a failed run on the rule's page; the support matrix lists which rules convert for Elastic EQL.

### "Detection engine permissions required"

The user needs Elastic Security privileges (the bench's `elastic` user has them). With your own cluster, give the user a role with the Security feature, and make sure the `.alerts-security.alerts-default` index can be created.

### No alerts

- Are the rules enabled? (`--enable`, or the toggle on the rule list)
- Are events arriving? `curl -s -u "elastic:$ES_PASSWORD" "http://localhost:9200/macos-telemetry-esf-*/_count?pretty"`
- Rules look back 6 minutes (correlations: their timespan more): events older than that when the rule first runs won't alert. To run them over older data, raise the look-back (bulk edit, **Update rule schedules**; Kibana takes hours, e.g. `72h`, not days). An ES|QL correlation also needs its last `| where timebucket ...` line removed: it alerts only on windows that closed in the last few minutes.
- Check the rule's status in the [support matrix](SUPPORT_MATRIX.md): many rules are not-verified, with the reason.

### Rules from 1.x are still there

Kibana keeps rules whose files were removed or turned into correlations in 2.0. The [changelog](../CHANGELOG.md) lists their IDs; delete them in **Security → Rules**.
