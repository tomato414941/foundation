# Foundation and OVHcloud, as the agent found them

The owner's connections that name OVHcloud (`foundation api GET /api/principals/OWNER/resources`, names only):

| name | method | state |
| --- | --- | --- |
| OVHcloud | ovh:api_key (OVHcloud · Enter API key) | ready |

What its consumer key may do (`GET /auth/currentCredential`):

- GET /vps, GET /vps/*, POST /vps/*, PUT /vps/*, DELETE /vps/*

The support API with it:

```
GET /support/tickets
403 {"class":"Client::Forbidden","message":"This call has not been granted"}
```

The connection methods Foundation offers for OVHcloud (`foundation api GET /api/connection-methods`):

- ovh:api_key (OVHcloud · Enter API key)
- ovh:consumer_key (OVHcloud · Connect in browser), access rules chosen as scopes
- ovh:client_credentials (OVHcloud · Connect with app credentials)
