# Docker Commands / Testing

1. Build docker image

```bash
docker build -t pixelnova-backend .
```

2. Run the container with environment variables:

```bash
docker run -p 8787:8787 --env-file .env pixelnova-backend
```

Test endpoints:

```bash
# Test health endpoint
curl http://localhost:8787/api/health

# Test protected endpoint with auth token
curl http://localhost:8787/api/protected \
 -H "Authorization: Bearer your_auth_token"
```

To stop and clean up:

```bash
# List containers
docker ps

# Stop container
docker stop <container_id>

# Remove container
docker rm <container_id>
```

## Docker Compose

For development with hot-reload, use docker-compose:

```bash
docker-compose up
```

This will mount the source code directories as volumes, allowing you to make changes and see them reflected immediately.

To rebuild the image:

```bash
docker-compose up --build
```
