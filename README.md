# Page Doctor

Deployable Node/Express app for the Meta-connected Page Doctor prototype.

## Render
Create a Web Service from this project.
Build Command: `npm install`
Start Command: `npm start`

Set these environment variables in Render:
- `META_APP_ID`
- `META_APP_SECRET`
- `APP_BASE_URL` = the exact public Render URL, without a trailing slash
- `META_GRAPH_VERSION=v26.0`
- `STATE_SECRET` = a long random secret

Then in Meta for Developers, under Facebook Login > Settings, set:
`https://YOUR-SERVICE.onrender.com/auth/meta/callback`
as a Valid OAuth Redirect URI.

## Important
Do not put META_APP_SECRET in the frontend or commit it to GitHub.

The app requests the Page-related permissions needed for the first real integration:
`pages_show_list`, `pages_read_engagement`, `pages_read_user_content`, `read_insights`.

Some permissions and Page Insights require Meta App Review/business requirements before they work for people other than app roles.

The current code deliberately handles unavailable metrics without pretending they are available. It is the integration foundation; the full diagnostic engine should be expanded after the first successful real Meta response.
