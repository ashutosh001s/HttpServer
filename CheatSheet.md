# Cheatsheet: Deploying HttpServer on AWS EC2 with HTTPS

## 1️⃣ Launch an EC2 Instance
- Use **Amazon Linux 2023**
- Allow **ports 22 (SSH), 80 (HTTP), and 443 (HTTPS)** in **Security Groups**

## 2️⃣ Connect to EC2
```bash
ssh -i api_server_key.pem ec2-user@your-ec2-public-ip
```

## 3️⃣ Install Required Packages
```bash
sudo yum update -y
sudo yum install -y gcc-c++ cmake git openssl-devel nginx certbot
```

## 4️⃣ Build & Run HttpServer
```bash
git clone https://github.com/your-repo/HttpServer.git
cd HttpServer
mkdir build && cd build
cmake ..
make
```

## 5️⃣ Get an SSL Certificate (Let's Encrypt)
```bash
sudo certbot certonly --standalone -d api.reqnode.com
```
- Certificates stored in `/etc/letsencrypt/live/api.reqnode.com/`

## 6️⃣ Set Environment Variables for SSL Paths
```bash
echo 'export SSL_CERT_PATH="/etc/letsencrypt/live/api.reqnode.com/fullchain.pem"' >> ~/.bashrc
echo 'export SSL_KEY_PATH="/etc/letsencrypt/live/api.reqnode.com/privkey.pem"' >> ~/.bashrc
source ~/.bashrc
```

## 7️⃣ Configure Nginx as a Reverse Proxy
```bash
sudo nano /etc/nginx/conf.d/httpserver.conf
```
Add the following configuration:
```nginx
server {
    listen 80;
    server_name api.reqnode.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
```bash
sudo systemctl restart nginx
```

## 8️⃣ Automate Deployment with GitHub Actions
Create `.github/workflows/deploy.yml` in your repository:
```yaml
name: Deploy to AWS
on:
  push:
    branches:
      - main
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v2

      - name: Deploy to EC2
        run: |
          ssh -o StrictHostKeyChecking=no ec2-user@your-ec2-public-ip << 'EOF'
          cd HttpServer && git pull origin main
          cd build && make
          sudo systemctl restart httpserver
          EOF
```

## 9️⃣ Run HttpServer with HTTPS
```bash
./HttpServer --port 8080 &
```

## 🔟 Test with Curl
```bash
curl -v https://api.reqnode.com/
```

## 🔁 Renew SSL Certificate (Every 3 Months)
```bash
sudo certbot renew
```

## ✅ Done! 🚀

