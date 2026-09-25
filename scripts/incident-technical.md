# Incident Report - Technical Detail (auto-generated draft)

**Period:** 24 Sep 2026, 00:00 to 25 Sep 2026, 00:00 (UTC)

## 1. Analyst notes

[YOU WRITE]

## 2. Failed logins by source IP

| Source IP | Failures | Distinct users | First seen | Last seen |
|---|---|---|---|---|
| 192.168.64.21 | 59 | 9 | 24 Sep 2026, 22:14:20 UTC | 24 Sep 2026, 23:02:56 UTC |

## 3. Successful logins

| Time | Source IP | User |
|---|---|---|
| 24 Sep 2026, 21:54:44 UTC | 192.168.64.1 | victim-ubuntu |
| 24 Sep 2026, 22:11:56 UTC | 192.168.64.1 | victim-ubuntu |
| 24 Sep 2026, 22:31:00 UTC | 192.168.64.21 | victim-ubuntu |
| 24 Sep 2026, 22:53:14 UTC | 192.168.64.21 | victim-ubuntu |

## 4. Alerts fired

| Rule | Times fired | First | Last |
|---|---|---|---|
| SSH Brute Force - Multiple Failed Logins (T1110.001) | 5 | 24 Sep 2026, 22:15:27 UTC | 24 Sep 2026, 23:03:28 UTC |
| SSH Successful Login After Brute Force (T1110 / T1078) | 1 | 24 Sep 2026, 22:31:52 UTC | 24 Sep 2026, 22:31:52 UTC |
| SSH Password Spraying - Many Usernames From One IP (T1110.003) | 2 | 24 Sep 2026, 22:35:46 UTC | 24 Sep 2026, 23:03:46 UTC |
| SSH Root Login Attempt (T1078.003) | 3 | 24 Sep 2026, 22:38:04 UTC | 24 Sep 2026, 23:03:07 UTC |
| New Local User Created (T1136.001) | 2 | 24 Sep 2026, 22:54:22 UTC | 24 Sep 2026, 22:58:22 UTC |
| User Added to Sudo Group (T1098) | 2 | 24 Sep 2026, 22:59:16 UTC | 24 Sep 2026, 22:59:16 UTC |

## 5. Impact

[YOU WRITE]

## 6. Recommendations (from playbooks)

### SSH Brute Force - Multiple Failed Logins (T1110.001)

**Investigate**
- Identify source IPs and targeted usernames
- Check whether any attempt succeeded

**Contain**
- Block the source IP at the firewall

**Prevent**
- Install fail2ban or rate-limit SSH
- Use SSH keys instead of passwords

### SSH Successful Login After Brute Force (T1110 / T1078)

**Investigate**
- Review commands run in the session (auth.log, last, shell history)

**Contain**
- Terminate the session
- Reset the account password
- Isolate the host

**Prevent**
- Enforce strong passwords or disable password login
- Enable MFA

### SSH Password Spraying - Many Usernames From One IP (T1110.003)

**Investigate**
- List which usernames were tried
- Check whether a real account was hit

**Contain**
- Block the source IP at the firewall
- Review the targeted accounts

**Prevent**
- Account lockout policy
- Monitor attempts on non-existent usernames

### SSH Root Login Attempt (T1078.003)

**Investigate**
- Check whether the attempt succeeded and from which IP

**Contain**
- Block the source IP at the firewall

**Prevent**
- Set PermitRootLogin no
- Require sudo from named accounts

### New Local User Created (T1136.001)

**Investigate**
- Who created the account (sudo user), when, in which session
- Check for added SSH keys and cron jobs

**Contain**
- Disable or delete the account

**Prevent**
- Restrict who can run useradd
- Alert on account changes

### User Added to Sudo Group (T1098)

**Investigate**
- Who made the change
- Did the user already run sudo commands

**Contain**
- Remove the user from the sudo group
- Treat the host as exposed

**Prevent**
- Least privilege
- Periodic review of sudo group members

