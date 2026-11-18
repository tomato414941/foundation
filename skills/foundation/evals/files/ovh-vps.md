# Foundation and OVHcloud, as the agent found them

The owner's connections that name OVHcloud (`foundation api GET /api/principals/OWNER/resources`, names only):

| name | method | state | outputs |
| --- | --- | --- | --- |
| OVHcloud | ovh:api_key (OVHcloud · Enter API key) | ready | OVH_APPLICATION_KEY, OVH_APPLICATION_SECRET, OVH_CONSUMER_KEY, OVH_API_BASE_URL |

What its consumer key may do (`GET /auth/currentCredential`):

- GET /vps, GET /vps/*, POST /vps/*, PUT /vps/*, DELETE /vps/*
