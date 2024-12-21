# Deploying to Fly.io

1. Install Flyctl if you haven't:

```bash
# macOS
brew install flyctl

# Windows
powershell -Command "iwr https://fly.io/install.ps1 -useb | iex"

# Linux
curl -L https://fly.io/install.sh | sh
```

2. Login to Fly.io:

```bash
fly auth login
```

3. Launch your app (first time only):

```bash
fly launch
```

4. Set up secrets (environment variables):

```bash
fly secrets set \
  SUPABASE_URL="your-supabase-url" \
  SUPABASE_SERVICE_ROLE_KEY="your-supabase-key" \
  OPEN_API_KEY="your-openai-key"
```

5. Deploy your application:

```bash
fly deploy
```

6. Check the deployment status:

```bash
fly status
```

7. View logs:

```bash
fly logs
```

8. Open your application:

```bash
fly open
```

## Useful Commands

Scale your app:

```bash
fly scale memory 512
fly scale vm shared-cpu-1x
```

Monitor your app:

```bash
fly status
fly logs
```

SSH into your app:

```bash
fly ssh console
```

## Troubleshooting

1. If deployment fails, check logs:

```bash
fly logs
```

2. If you need to restart:

```bash
fly apps restart
```

3. To check resource usage:

```bash
fly status
```

4. To scale down when not in use:

```bash
fly scale count 0
```

5. To scale back up:

```bash
fly scale count 1
```
