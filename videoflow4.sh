#!/bin/bash

# M3U8 直播流转发工具 - 简化版
# 添加了自动续签功能

# 颜色设置
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 检查root权限
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}错误: 请使用root权限运行此脚本${NC}"
    exit 1
fi

# 创建备份目录
BACKUP_DIR="/tmp/m3u8proxy_backup_$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"

# 备份函数
backup_file() {
    if [ -f "$1" ]; then
        cp "$1" "$BACKUP_DIR/$(basename "$1")"
        echo -e "${BLUE}已备份: $1${NC}"
    fi
}

# 恢复函数
restore_backup() {
    echo -e "${YELLOW}正在恢复原始配置...${NC}"
    
    for file in "$BACKUP_DIR"/*; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            if [[ "$filename" == "nginx.conf" ]]; then
                cp "$file" "/etc/nginx/nginx.conf"
                echo -e "${GREEN}已恢复 nginx.conf${NC}"
            elif [[ "$filename" == *.conf ]]; then
                cp "$file" "/etc/nginx/sites-available/$filename"
                echo -e "${GREEN}已恢复站点配置: $filename${NC}"
            fi
        fi
    done
    
    systemctl restart nginx
    echo -e "${GREEN}恢复完成${NC}"
}

# 检查并安装依赖
install_dependencies() {
    echo -e "${BLUE}检查并安装必要依赖...${NC}"
    
    apt update
    
    # 安装nginx
    if ! command -v nginx &>/dev/null; then
        echo -e "${YELLOW}安装 Nginx...${NC}"
        apt install -y nginx
    else
        echo -e "${GREEN}Nginx 已安装${NC}"
    fi
    
    # 安装htpasswd
    if ! command -v htpasswd &>/dev/null; then
        echo -e "${YELLOW}安装 apache2-utils...${NC}"
        apt install -y apache2-utils
    else
        echo -e "${GREEN}htpasswd 已安装${NC}"
    fi
    
    # 安装certbot
    if ! command -v certbot &>/dev/null; then
        echo -e "${YELLOW}安装 certbot...${NC}"
        apt install -y certbot python3-certbot-nginx
    else
        echo -e "${GREEN}Certbot 已安装${NC}"
    fi
    
    echo -e "${GREEN}所有依赖已安装${NC}"
}

# 配置Nginx
configure_nginx() {
    local domain="$1"
    local source_url="$2"
    local stream_path="$3"
    local cert_dir="/root/cert/$domain"
    
    echo -e "${BLUE}配置 Nginx...${NC}"
    
    # 备份nginx配置
    backup_file "/etc/nginx/nginx.conf"
    
    # 创建证书目录
    mkdir -p "$cert_dir"
    
    # 更新nginx.conf
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    log_format auth_log '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent"';

    gzip on;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # 获取源URL的主机
    local source_host=$(echo "$source_url" | awk -F/ '{print $3}')
    
    # 创建站点配置
    local site_config="/etc/nginx/sites-available/$domain.conf"
    backup_file "$site_config"
    
    cat > "$site_config" << EOF
# HTTPS Server Block for $domain
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $domain;

    ssl_certificate $cert_dir/fullchain.pem;
    ssl_certificate_key $cert_dir/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    location /$stream_path/ {
        auth_basic "Password Protected Stream";
        auth_basic_user_file /etc/nginx/.htpasswd;

        proxy_pass https://$source_host/;
        proxy_set_header Host $source_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        proxy_redirect off;

        access_log /var/log/nginx/m3u8_auth.log auth_log;
    }

    location / {
        return 403 "Forbidden";
    }
}

# HTTP to HTTPS Redirect
server {
    listen 80;
    listen [::]:80;
    server_name $domain;
    return 301 https://\$host\$request_uri;
}
EOF

    # 启用站点
    if [ ! -L "/etc/nginx/sites-enabled/$domain.conf" ]; then
        ln -s "$site_config" "/etc/nginx/sites-enabled/$domain.conf"
    fi
    
    echo -e "${GREEN}Nginx 配置完成${NC}"
}

# 创建密码文件
create_password_file() {
    local username="$1"
    local password="$2"
    
    echo -e "${BLUE}创建密码保护...${NC}"
    htpasswd -bc /etc/nginx/.htpasswd "$username" "$password"
    echo -e "${GREEN}密码保护已配置${NC}"
}

# 设置SSL证书
setup_ssl_certificate() {
    local domain="$1"
    local cert_dir="/root/cert/$domain"
    
    echo -e "${BLUE}设置 SSL 证书...${NC}"
    mkdir -p "$cert_dir"
    
    if [ -f "$cert_dir/fullchain.pem" ] && [ -f "$cert_dir/privkey.pem" ]; then
        echo -e "${GREEN}SSL 证书已存在${NC}"
        return
    fi
    
    echo -e "${YELLOW}申请 SSL 证书...${NC}"
    certbot certonly --standalone --preferred-challenges http \
        --agree-tos --email "admin@$domain" -d "$domain"
    
    if [ -d "/etc/letsencrypt/live/$domain" ]; then
        cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$cert_dir/"
        cp "/etc/letsencrypt/live/$domain/privkey.pem" "$cert_dir/"
        echo -e "${GREEN}SSL 证书已设置${NC}"
    else
        echo -e "${RED}无法获取 SSL 证书${NC}"
    fi
}

# 设置证书自动续签
setup_cert_renewal() {
    echo -e "${BLUE}设置证书自动续签...${NC}"
    
    # 创建自动续签脚本
    cat > /root/renew_cert.sh << 'EOF'
#!/bin/bash
# 证书自动续签脚本

certbot renew --quiet
systemctl reload nginx
EOF

    chmod +x /root/renew_cert.sh
    
    # 添加到crontab
    (crontab -l 2>/dev/null || echo "") | grep -v "renew_cert.sh" | { cat; echo "0 3 * * * /root/renew_cert.sh > /dev/null 2>&1"; } | crontab -
    
    echo -e "${GREEN}证书自动续签已设置 (每天凌晨3点)${NC}"
}

# 显示帮助
show_help() {
    echo -e "${BLUE}M3U8 直播流转发配置脚本${NC}"
    echo -e "${YELLOW}用法:${NC}"
    echo -e "  $0 [命令] 或 [参数]"
    echo -e ""
    echo -e "${YELLOW}命令:${NC}"
    echo -e "  setup     - 交互式设置"
    echo -e "  restore   - 恢复原始配置"
    echo -e "  help      - 显示帮助"
    echo -e ""
    echo -e "${YELLOW}一次性设置格式:${NC}"
    echo -e "  $0 domain source_url stream_path username password"
    echo -e ""
    echo -e "${YELLOW}示例:${NC}"
    echo -e "  $0 news.example.com https://source.com/index_1.m3u8 live admin password123"
}

# 主函数
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}   M3U8 直播流转发配置工具${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    if [ "$1" == "help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        show_help
        exit 0
    elif [ "$1" == "restore" ]; then
        restore_backup
        exit 0
    elif [ "$#" -eq 5 ]; then
        # 一次性设置模式
        domain="$1"
        source_url="$2"
        stream_path="$3"
        username="$4"
        password="$5"
        
        echo -e "${GREEN}使用提供的参数:${NC}"
        echo -e "域名: ${YELLOW}$domain${NC}"
        echo -e "源URL: ${YELLOW}$source_url${NC}"
        echo -e "流路径: ${YELLOW}$stream_path${NC}"
        echo -e "用户名: ${YELLOW}$username${NC}"
        echo -e "密码: ${YELLOW}****${NC}"
    elif [ "$1" == "setup" ] || [ -z "$1" ]; then
        # 交互式模式
        echo -e "${GREEN}交互式设置:${NC}"
        
        read -p "请输入域名: " domain
        read -p "请输入源直播URL: " source_url
        read -p "请输入转发路径: " stream_path
        read -p "请输入访问用户名: " username
        read -p "请输入访问密码: " password
    else
        echo -e "${RED}参数错误!${NC}"
        show_help
        exit 1
    fi
    
    # 执行设置
    install_dependencies
    create_password_file "$username" "$password"
    setup_ssl_certificate "$domain" 
    configure_nginx "$domain" "$source_url" "$stream_path"
    setup_cert_renewal
    
    # 重启Nginx
    systemctl restart nginx
    
    # 显示结果
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}配置完成!${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "您的直播流地址: ${YELLOW}https://$domain/$stream_path/${NC}"
    echo -e "用户名: ${YELLOW}$username${NC}"
    echo -e "密码: ${YELLOW}$password${NC}"
    echo -e ""
    echo -e "证书将每天自动续签"
    echo -e "恢复配置命令: ${YELLOW}$0 restore${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# 执行主函数
main "$@"