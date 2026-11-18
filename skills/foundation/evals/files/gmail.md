# Foundation and Google, as the agent found them

The owner's Google connections (`foundation api GET /api/principals/OWNER/resources`, names only):

| name | method | state | scopes |
| --- | --- | --- | --- |
| user@example.com | google:oauth (Google · Connect in browser) | uncertain | gmail.readonly, gmail.send, userinfo.email, openid |
| team@example.com | google:oauth (Google · Connect in browser) | uncertain | gmail.readonly, userinfo.email, openid |

Using the first one:

```
foundation exec --inputs '[{"name":"GOOGLE_OAUTH_ACCESS_TOKEN","source":{"id":"ID","output":"GOOGLE_OAUTH_ACCESS_TOKEN"}}]' -- python3 gmail_look.py
foundation: Reconnect this service to renew access.
```
