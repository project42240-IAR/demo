# Vercel Deployment Guide

This project is configured for one-click deployment on **Vercel** via serverless Python functions (`@vercel/python`).

## Files Created

- [`vercel.json`](./vercel.json): Serverless routing and `@vercel/python` builder config.
- [`.vercelignore`](./.vercelignore): Excludes `.env`, local caches, and build artifacts from Vercel deployment builds.

---

## Deployment Steps

### Method 1: GitHub Automatic Deployment (Recommended)

1. Go to [Vercel New Project](https://vercel.com/new).
2. Select & Import your GitHub repository: `project42240-IAR/demo`.
3. Expand **Environment Variables** and add the following keys from your `.env.local`:

| Environment Variable | Description / Source |
| --- | --- |
| `SUPABASE_URL` | Your Supabase Project URL |
| `SUPABASE_PUBLISHABLE_KEY` | Your Supabase Publishable Key |
| `SUPABASE_SECRET_KEY` | Your Supabase Secret Service Role Key |
| `SUPABASE_REST_URL` | `https://your-project.supabase.co/rest/v1/` |
| `NEXT_PUBLIC_SUPABASE_URL` | Your Supabase Project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Your Supabase Publishable Key |

4. Click **Deploy**.

---

### Method 2: Vercel CLI

Run the following commands in your terminal:

```bash
# 1. Login to Vercel
npx vercel login

# 2. Deploy Preview
npx vercel

# 3. Deploy to Production
npx vercel --prod
```
