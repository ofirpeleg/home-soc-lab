# Detection Rules

Six custom rules, all Kibana Stack Rules of type **Elasticsearch query (ES|QL)**.
Common settings: time field `@timestamp`, look-back window 5 minutes, check every 1 minute,
"Create an alert for each row", no actions.

The MITRE ATT&CK technique ID is part of each rule name and the rule tags. Kibana's dedicated
Security detection engine (which has a native ATT&CK field) requires `xpack.security` to be enabled;
this lab runs with it disabled, so the generic alerting framework is used instead.

| # | Rule | MITRE ATT&CK | Tag |
|---|---|---|---|
| 1 | SSH Brute Force - Multiple Failed Logins | T1110.001 | `SSH_Brute_Force` |
| 2 | SSH Successful Login After Brute Force | T1110 / T1078 | `SSH_Compromise` |
| 3 | SSH Password Spraying - Many Usernames From One IP | T1110.003 | `SSH_Spraying` |
| 4 | SSH Root Login Attempt | T1078.003 | `SSH_Root` |
| 5 | New Local User Created | T1136.001 | `Persistence` |
| 6 | User Added to Sudo Group | T1098 | `Privilege_Escalation` |

## 1. SSH Brute Force (T1110.001)
More than 3 failed logins from one source IP.
```
FROM logs-victim.auth-*
| WHERE event.outcome == "failure"
| STATS failures = COUNT(*) BY source.ip
| WHERE failures > 3
| KEEP source.ip, failures
```
Test: `hydra -l victim-ubuntu -P wrong.txt ssh://<victim-ip> -t 4`

## 2. Successful Login After Brute Force (T1110 / T1078)
Same source IP has more than 3 failures and at least one success in the window.
```
FROM logs-victim.auth-*
| STATS failures = COUNT(*) WHERE event.outcome == "failure", successes = COUNT(*) WHERE event.outcome == "success" BY source.ip
| WHERE failures > 3 AND successes > 0
| KEEP source.ip, failures, successes
```
Test: hydra with a wordlist where the valid password comes last, `-t 1`.

## 3. Password Spraying (T1110.003)
More than 3 distinct usernames tried from one source IP.
```
FROM logs-victim.auth-*
| WHERE event.outcome == "failure"
| STATS distinct_users = COUNT_DISTINCT(user.name), attempts = COUNT(*) BY source.ip
| WHERE distinct_users > 3
| KEEP source.ip, distinct_users, attempts
```
Test: `hydra -L users.txt -p wrongpass ssh://<victim-ip> -t 4`

## 4. Root Login Attempt (T1078.003)
Any SSH attempt targeting `root`.
```
FROM logs-victim.auth-*
| WHERE user.name == "root"
| STATS attempts = COUNT(*), failures = COUNT(*) WHERE event.outcome == "failure", successes = COUNT(*) WHERE event.outcome == "success" BY source.ip
| KEEP source.ip, attempts, failures, successes
```
Test: `ssh root@<victim-ip>` with a wrong password.

## 5. New Local User Created (T1136.001)
`useradd` writes `new user: name=...` to `auth.log`.
```
FROM logs-victim.auth-*
| WHERE message LIKE "*new user: name=*"
| KEEP @timestamp, host.name, message
```
Test (on the victim): `sudo useradd hacker`

## 6. User Added to Sudo Group (T1098)
```
FROM logs-victim.auth-*
| WHERE message LIKE "*to group 'sudo'*" OR message LIKE "*to shadow group 'sudo'*"
| KEEP @timestamp, host.name, message
```
Test (on the victim): `sudo usermod -aG sudo hacker2`
