# Phase 5: Notifications and Ticketing — Design

**Date:** 2026-10-30 · **Status:** approved · Roadmap: `2026-10-30-enterprise-roadmap-and-phase1-rbac-design.md`

## Channels (admin only, `integrations.manage`)

| Kind | Config | Secret (encrypted) | Delivery |
|---|---|---|---|
| webhook | URL | optional signing secret | JSON `{event,title,text,severity,url,fields,data}`, `X-ZDRS-Signature: sha256=<hmac>` |
| slack | — | incoming webhook URL | Block Kit message |
| teams | — | Workflows webhook URL | Adaptive Card 1.4 |
| email | recipients, also-to-assignee | — (SMTP password lives in Settings) | SMTP (none / STARTTLS / SSL) |
| jira | base URL, account email, project key, issue type | API token | REST v2: create, comment, transition to a *done* status, poll status |
| gitlab | base URL, project id or path, labels | access token | REST v4: create, note, close / reopen, poll state |

Every channel has **Send test**. Secrets are encrypted with Fernet (key derived from the instance
`secret_key`), never rendered back; a blank secret field keeps the stored value.

## Rules

`channel + events + minimum severity + optional scope`. Events: `issue.created`, `issue.reopened`,
`issue.overdue`, `issue.assigned`, `issue.status_changed`, `campaign.created`, `scan.problem` (job failed or
done with warnings), `schedule.error`. For Jira / GitLab channels only `issue.created` and `issue.reopened`
are meaningful: they create (or reopen) a ticket.

## Tickets (two-way)

- `issue_tickets` links an issue to an external ticket (key, URL, state). Created by a rule or the
  "Create ticket" button on the issue page (`issues.manage`).
- Issue → ticket: fixed adds a comment; verified / false positive / accepted risk comment and close;
  reopened comments and reopens (GitLab) or comments (Jira).
- Ticket → issue: every 15 minutes open tickets are polled; a ticket closed externally moves an
  open-work issue to **fixed** (timeline: "Ticket … closed in Jira") without echoing back to the ticket.

## Delivery

All messages go through an outbox (`notification_deliveries`). A background loop (10 s) sends due rows;
failures retry after 1, 5, 15 and 60 minutes, then become *failed*. Delivery log page with status filter and
retry. Overdue notifications are sent once per issue (`issues.overdue_notified_at`). Scan problems are found
by a job cursor.

## Settings

Public URL (links in messages) and SMTP server (host, port, security, user, password, from).

## Testing

Secret box, payload formats and signatures, Jira / GitLab operations against a fake HTTP client, email via a
fake SMTP sender, rule matching, outbox retries, ticket sync both ways, routes, permissions, audit.
