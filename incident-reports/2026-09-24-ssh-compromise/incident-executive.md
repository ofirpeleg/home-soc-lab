# Security Incident Briefing

**Period:** 24 Sep 2026, 00:00 to 25 Sep 2026, 00:00 (UTC)  
**Severity:** HIGH

## What happened

Between 24 Sep 2026, 22:14:20 UTC and 24 Sep 2026, 23:02:56 UTC, a device on the internal network (192.168.64.21) made 59 failed attempts to sign in to server ubuntu-server, trying 9 different accounts. It succeeded 2 time(s), the first at 24 Sep 2026, 22:31:00 UTC. After signing in, changes to user accounts and permissions were made.

## Business impact

The server should be treated as compromised: an unauthorized party logged in and changed accounts or privileges.

## How it was detected

Automated monitoring raised 15 alert(s) from 6 of 6 detection rules. The first alert appeared about 1 minute(s) after the first suspicious attempt.

## Recommended actions

**Immediate (today)**
- Disconnect the suspicious sign-in and reset the password of the affected account
- Take the server off the network until it has been checked
- Disable the unknown account that was created on the server
- Remove the extra administrator rights that were granted
- Block the attacking device from reaching the server

**Next steps (prevent recurrence)**
- Require strong passwords and a second verification step (MFA) for remote access
- Limit who is allowed to create accounts on servers
- Review who has administrator rights on each server on a regular schedule
- Automatically block devices after repeated failed sign-ins
- Use secure keys instead of passwords for remote server access

A detailed technical report is available separately.

