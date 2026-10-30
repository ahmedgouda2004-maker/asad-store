# ASAD store

Node + Express + Postgres (Supabase). One service serves the API and the website.

## Features
- Mandatory sign up / log in, email OTP verification, bcrypt-hashed passwords, JWT sessions
- Accounts, products and orders live in Postgres, so they sync across phone and laptop
- Owner account (set with ADMIN_USER / ADMIN_PASS) sees the Dashboard: users, orders, sales, and the Add-a-cap form. The server rejects these calls for everyone else.
- Shop with 3 seeded caps (edit prices in the DB or add caps from the dashboard), prices in L.E
- Make-your-own cap: front/back view, color swatches, front/back text, synced to the cart
- Order prices are recalculated on the server; checkout is pay on delivery

## Deploy (free tier, about 15 minutes)
1. **Database**: create a project at supabase.com. Copy the connection string (URI) into `DATABASE_URL`. Tables are created automatically on first start.
2. **Email**: for Gmail, turn on 2-step verification, create an App Password, use `smtp.gmail.com`, port `465`.
3. **Code**: push this folder to a new GitHub repo.
4. **Host**: at render.com choose New > Web Service, connect the repo.
   Build command `npm install`, start command `npm start`.
5. **Environment variables** on Render: everything in `.env.example`.
   Set `ADMIN_USER=gouda_co` and `ADMIN_PASS` to the owner password you want. The password is never stored in the code.
6. Open the `https://your-app.onrender.com` URL on any phone or laptop.

## Run locally
```
npm install
cp .env.example .env   # fill it in, then export the variables (or use: node --env-file=.env server.js)
npm start
```
Without SMTP settings and outside production, the OTP is printed in the server console.

## Notes
- Change `ADMIN_PASS` and redeploy any time to rotate the owner password.
- Cart contents are kept in the browser so a refresh does not lose them; orders, accounts and products are in the database.
- Render's free tier sleeps after inactivity, so the first visit can take ~30 seconds.
