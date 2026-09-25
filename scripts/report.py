import argparse
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests

ES = "http://localhost:9200"
LOGS = "logs-victim.auth-*"
ALERTS = ".alerts-stack.alerts-default"
TOTAL_RULES = 6

# Technical playbooks (used in the technical report): rule name prefix -> actions
PLAYBOOKS = {
    "SSH Brute Force": {
        "investigate": ["Identify source IPs and targeted usernames", "Check whether any attempt succeeded"],
        "contain": ["Block the source IP at the firewall"],
        "prevent": ["Install fail2ban or rate-limit SSH", "Use SSH keys instead of passwords"],
    },
    "SSH Successful Login After Brute Force": {
        "investigate": ["Review commands run in the session (auth.log, last, shell history)"],
        "contain": ["Terminate the session", "Reset the account password", "Isolate the host"],
        "prevent": ["Enforce strong passwords or disable password login", "Enable MFA"],
    },
    "SSH Password Spraying": {
        "investigate": ["List which usernames were tried", "Check whether a real account was hit"],
        "contain": ["Block the source IP at the firewall", "Review the targeted accounts"],
        "prevent": ["Account lockout policy", "Monitor attempts on non-existent usernames"],
    },
    "SSH Root Login Attempt": {
        "investigate": ["Check whether the attempt succeeded and from which IP"],
        "contain": ["Block the source IP at the firewall"],
        "prevent": ["Set PermitRootLogin no", "Require sudo from named accounts"],
    },
    "New Local User Created": {
        "investigate": ["Who created the account (sudo user), when, in which session", "Check for added SSH keys and cron jobs"],
        "contain": ["Disable or delete the account"],
        "prevent": ["Restrict who can run useradd", "Alert on account changes"],
    },
    "User Added to Sudo Group": {
        "investigate": ["Who made the change", "Did the user already run sudo commands"],
        "contain": ["Remove the user from the sudo group", "Treat the host as exposed"],
        "prevent": ["Least privilege", "Periodic review of sudo group members"],
    },
}

# Plain-language actions for the management briefing.
# Listed in priority order: most serious incident types first.
EXEC_ACTIONS = [
    ("SSH Successful Login After Brute Force", {
        "now": ["Disconnect the suspicious sign-in and reset the password of the affected account",
                "Take the server off the network until it has been checked"],
        "next": ["Require strong passwords and a second verification step (MFA) for remote access"],
    }),
    ("New Local User Created", {
        "now": ["Disable the unknown account that was created on the server"],
        "next": ["Limit who is allowed to create accounts on servers"],
    }),
    ("User Added to Sudo Group", {
        "now": ["Remove the extra administrator rights that were granted"],
        "next": ["Review who has administrator rights on each server on a regular schedule"],
    }),
    ("SSH Brute Force", {
        "now": ["Block the attacking device from reaching the server"],
        "next": ["Automatically block devices after repeated failed sign-ins",
                 "Use secure keys instead of passwords for remote server access"],
    }),
    ("SSH Password Spraying", {
        "now": ["Check whether any of the accounts that were tried belong to real users"],
        "next": ["Lock accounts temporarily after repeated failed attempts"],
    }),
    ("SSH Root Login Attempt", {
        "now": ["Block the attacking device from reaching the server"],
        "next": ["Disable direct remote sign-in to the most powerful (root) account"],
    }),
]
MAX_ACTIONS = 5


def parse_when(s, tz):
    fmt_in = "%Y-%m-%d %H:%M" if " " in s else "%Y-%m-%d"
    return datetime.strptime(s, fmt_in).replace(tzinfo=tz)


def to_dt(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def fmt(iso, tz):
    dt = to_dt(iso).astimezone(tz)
    return dt.strftime("%d %b %Y, %H:%M:%S ") + dt.tzname()


def utc(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def search(index, body):
    r = requests.post(f"{ES}/{index}/_search", json=body, timeout=10)
    r.raise_for_status()
    return r.json()


def unique(items):
    seen = []
    for i in items:
        if i not in seen:
            seen.append(i)
    return seen


p = argparse.ArgumentParser()
p.add_argument("--date", help="single day, e.g. 2026-09-24")
p.add_argument("--start", help='e.g. "2026-09-24 22:00"')
p.add_argument("--end", help='e.g. "2026-09-25 00:00"')
p.add_argument("--tz", default="UTC", help="input/display timezone, default UTC (e.g. Asia/Jerusalem)")
p.add_argument("--out", default="incident-technical.md", help="technical report file")
p.add_argument("--exec-out", default="incident-executive.md", help="management briefing file")
args = p.parse_args()

tz = ZoneInfo(args.tz)
if args.date:
    start = parse_when(args.date, tz)
    end = start + timedelta(days=1)
elif args.start and args.end:
    start, end = parse_when(args.start, tz), parse_when(args.end, tz)
else:
    p.error("use --date, or both --start and --end")

time_range = {"range": {"@timestamp": {"gte": utc(start), "lt": utc(end)}}}

fails = search(LOGS, {
    "size": 0,
    "track_total_hits": True,
    "query": {"bool": {"filter": [{"term": {"event.outcome": "failure"}}, time_range]}},
    "aggs": {
        "by_ip": {"terms": {"field": "source.ip", "size": 10},
                  "aggs": {"users": {"cardinality": {"field": "user.name"}},
                           "first": {"min": {"field": "@timestamp"}},
                           "last": {"max": {"field": "@timestamp"}}}},
        "users_total": {"cardinality": {"field": "user.name"}},
        "hosts": {"terms": {"field": "host.name", "size": 3}},
    },
})

succ = search(LOGS, {
    "size": 50, "sort": [{"@timestamp": "asc"}],
    "query": {"bool": {"filter": [{"term": {"event.outcome": "success"}}, time_range]}},
    "_source": ["@timestamp", "source.ip", "user.name"],
})

alerts = search(ALERTS, {
    "size": 200, "sort": [{"kibana.alert.start": "asc"}],
    "query": {"range": {"kibana.alert.start": {"gte": utc(start), "lt": utc(end)}}},
    "_source": ["kibana.alert.rule.name", "kibana.alert.start"],
})

# ---- derived data ----
buckets = fails["aggregations"]["by_ip"]["buckets"]
attacker_ips = [b["key"] for b in buckets]
total_fail = fails["hits"]["total"]["value"]
users_targeted = int(fails["aggregations"]["users_total"]["value"])
hosts = [b["key"] for b in fails["aggregations"]["hosts"]["buckets"]]

attacker_success = [h["_source"] for h in succ["hits"]["hits"]
                    if h["_source"]["source"]["ip"] in attacker_ips]

by_rule = {}
for h in alerts["hits"]["hits"]:
    s = h["_source"]
    by_rule.setdefault(s["kibana.alert.rule.name"], []).append(s["kibana.alert.start"])
fired = list(by_rule)
total_alerts = sum(len(v) for v in by_rule.values())
followup = [n for n in fired if n.startswith(("New Local User Created", "User Added to Sudo Group"))]

first_fail = min((b["first"]["value_as_string"] for b in buckets), default=None)
last_fail = max((b["last"]["value_as_string"] for b in buckets), default=None)
first_alert = min((t for times in by_rule.values() for t in times), default=None)

if attacker_success and followup:
    level = "HIGH"
    verdict = "The server should be treated as compromised: an unauthorized party logged in and changed accounts or privileges."
elif attacker_success:
    level = "HIGH"
    verdict = "The server should be treated as compromised: an unauthorized party logged in successfully."
elif total_fail:
    level = "MEDIUM"
    verdict = "An attack was attempted but no successful unauthorized login was detected."
else:
    level = "LOW"
    verdict = "No attack activity was detected."

# ---- technical report ----
out = []
out.append("# Incident Report - Technical Detail (auto-generated draft)\n")
out.append(f"**Period:** {start:%d %b %Y, %H:%M} to {end:%d %b %Y, %H:%M} ({args.tz})\n")
out.append("## 1. Analyst notes\n\n[YOU WRITE]\n")

out.append("## 2. Failed logins by source IP\n")
out.append("| Source IP | Failures | Distinct users | First seen | Last seen |\n|---|---|---|---|---|")
for b in buckets:
    out.append(f"| {b['key']} | {b['doc_count']} | {b['users']['value']} | "
               f"{fmt(b['first']['value_as_string'], tz)} | {fmt(b['last']['value_as_string'], tz)} |")

out.append("\n## 3. Successful logins\n")
out.append("| Time | Source IP | User |\n|---|---|---|")
for h in succ["hits"]["hits"]:
    s = h["_source"]
    out.append(f"| {fmt(s['@timestamp'], tz)} | {s['source']['ip']} | {s['user']['name']} |")

out.append("\n## 4. Alerts fired\n")
out.append("| Rule | Times fired | First | Last |\n|---|---|---|---|")
for name, times in by_rule.items():
    out.append(f"| {name} | {len(times)} | {fmt(min(times), tz)} | {fmt(max(times), tz)} |")

out.append("\n## 5. Impact\n\n[YOU WRITE]\n")
out.append("## 6. Recommendations (from playbooks)\n")
for name in fired:
    for key, pb in PLAYBOOKS.items():
        if name.startswith(key):
            out.append(f"### {name}\n")
            for title, items in (("Investigate", pb["investigate"]), ("Contain", pb["contain"]), ("Prevent", pb["prevent"])):
                out.append(f"**{title}**")
                out.extend(f"- {i}" for i in items)
                out.append("")

with open(args.out, "w") as f:
    f.write("\n".join(out) + "\n")

# ---- executive (management) briefing ----
ex = []
ex.append("# Security Incident Briefing\n")
ex.append(f"**Period:** {start:%d %b %Y, %H:%M} to {end:%d %b %Y, %H:%M} ({args.tz})  ")
ex.append(f"**Severity:** {level}\n")
ex.append("## What happened\n")
if total_fail == 0:
    ex.append("No suspicious sign-in activity was recorded in this period.\n")
else:
    text = (f"Between {fmt(first_fail, tz)} and {fmt(last_fail, tz)}, a device on the internal network "
            f"({', '.join(attacker_ips)}) made {total_fail} failed attempts to sign in to server "
            f"{', '.join(hosts)}, trying {users_targeted} different accounts.")
    if attacker_success:
        text += (f" It succeeded {len(attacker_success)} time(s), the first at "
                 f"{fmt(attacker_success[0]['@timestamp'], tz)}.")
    else:
        text += " None of these attempts succeeded."
    if followup:
        text += " After signing in, changes to user accounts and permissions were made."
    ex.append(text + "\n")

ex.append("## Business impact\n")
ex.append(verdict + "\n")

ex.append("## How it was detected\n")
if first_alert and first_fail:
    minutes = max(0, round((to_dt(first_alert) - to_dt(first_fail)).total_seconds() / 60))
    ex.append(f"Automated monitoring raised {total_alerts} alert(s) from {len(fired)} of {TOTAL_RULES} detection rules. "
              f"The first alert appeared about {minutes} minute(s) after the first suspicious attempt.\n")
else:
    ex.append("No alerts were raised in this period.\n")

ex.append("## Recommended actions\n")
immediate, next_steps = [], []
for key, actions in EXEC_ACTIONS:
    if any(n.startswith(key) for n in fired):
        immediate += actions["now"]
        next_steps += actions["next"]
ex.append("**Immediate (today)**")
ex.extend(f"- {i}" for i in unique(immediate)[:MAX_ACTIONS])
ex.append("\n**Next steps (prevent recurrence)**")
ex.extend(f"- {i}" for i in unique(next_steps)[:MAX_ACTIONS])
ex.append("\nA detailed technical report is available separately.\n")

with open(args.exec_out, "w") as f:
    f.write("\n".join(ex) + "\n")

print("Wrote", args.out, "and", args.exec_out)
