# Production Deploy Guide

This repo now includes a production deployment path that keeps `postgres` and
`ai-service` private inside Docker while exposing only the reverse proxy.

## 1. Prepare the server

Install Docker, Compose, Nginx, Certbot, and a firewall:

```bash
sudo apt update
sudo apt install -y git nginx ufw certbot python3-certbot-nginx
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
newgrp docker
```

Open only SSH, HTTP, and HTTPS:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable
```

## 2. Copy the app to the server

```bash
sudo mkdir -p /opt/fpipay
sudo chown "$USER":"$USER" /opt/fpipay
cd /opt/fpipay
git clone <your-repo-url> .
cp .env.example .env
```

## 3. Fill the production env

Edit `.env` and set at minimum:

- `NODE_ENV=production`
- `APP_BASE_URL=https://your-domain.com`
- `ALLOWED_ORIGINS=https://your-domain.com,https://www.your-domain.com`
- `POSTGRES_PASSWORD=<strong password>`
- `DATABASE_URL=postgresql://postgres:<same password>@postgres:5432/ewallet`
- `JWT_SECRET=<long random secret>`
- `ENCRYPTION_KEY=<32-byte base64 or 64-char hex key>`
- `BOOTSTRAP_DEFAULT_ADMIN=1`
- `DEFAULT_ADMIN_EMAIL=<your admin email>`
- `DEFAULT_ADMIN_PASSWORD=<temporary strong password>`
- SMTP credentials if you use email OTP

Generate a valid encryption key with:

```bash
openssl rand -base64 32
```

## 4. Start the production stack

```bash
docker compose -f infra/docker-compose.prod.yml up -d --build
```

If you want to create the schema immediately:

```bash
docker compose -f infra/docker-compose.prod.yml exec api \
  npx prisma db push --schema /app/prisma/schema.prisma
```

After your first successful login, disable bootstrap admin creation:

```bash
sed -i 's/^BOOTSTRAP_DEFAULT_ADMIN=1/BOOTSTRAP_DEFAULT_ADMIN=0/' .env
docker compose -f infra/docker-compose.prod.yml up -d
```

## 5. Configure Nginx on the host

Copy the template and replace the domain names:

```bash
sudo cp infra/nginx-fpipay.conf /etc/nginx/sites-available/fpipay
sudo nano /etc/nginx/sites-available/fpipay
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/fpipay /etc/nginx/sites-enabled/fpipay
sudo nginx -t
sudo systemctl restart nginx
```

## 6. Add HTTPS

```bash
sudo certbot --nginx -d your-domain.com -d www.your-domain.com
```

## 7. Verify

```bash
docker compose -f infra/docker-compose.prod.yml ps
curl http://127.0.0.1:4000/health
curl http://127.0.0.1:8080/health
```

## Security checklist

- Keep only ports `22`, `80`, and `443` open to the internet.
- Do not expose Docker's `5432` or `8000` publicly.
- Rotate `DEFAULT_ADMIN_PASSWORD` after first login.
- Set `BOOTSTRAP_DEFAULT_ADMIN=0` after the initial admin account exists.
- Keep `.env` out of git.
