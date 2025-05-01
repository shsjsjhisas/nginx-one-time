#!/bin/bash

# M3U8 直播转发工具
# 作者: AI Assistant
# 版本: 1.0

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 全局变量
DOMAIN=""
SOURCE_URL=""
LOCAL_PATH=""
USERNAME="admin"
PASSWORD="admin123"
CERT_DIR="/root/cert"
BACKUP_DIR="/root/nginx_backup_$(date +%Y%m%d%H%M%S)"
NGINX_CONF="/etc/nginx/nginx.conf"
SITE_CONF="/etc/nginx/sites-available/default"
SITE_ENABLED="/etc/nginx/sites-enabled/default"
PASSWD_FILE="/etc/nginx/.htpasswd"
USE_DEFAULT_PASSWORD=false

# 标题展示
show_banner() {
    clear
    echo -e "${BLUE}====================================================${NC}"
    echo -e "${GREEN}         M3U8 直播转发工具 v1.0                   ${NC}"
    echo -e "${BLUE}====================================================${NC}"
    echo ""
}

# 检查是否为 root 用户
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误：此脚本需要以 root 权限运行${NC}" >&2
        exit 1
    fi
}

# 检查依赖项
check_dependencies() {
    echo -e "${YELLOW}正在检查必要的依赖...${NC}"
    
    # 创建备份目录
    mkdir -p $BACKUP_DIR
    
    # 安装基本依赖
    apt update
    
    # 检查并安装 Nginx
    if ! command -v nginx >/dev/null 2>&1; then
        echo -e "${YELLOW}安装 Nginx...${NC}"
        apt install -y nginx
    else
        echo -e "${GREEN}Nginx 已安装${NC}"
    fi
    
    # 检查并安装 Apache2 Utils (htpasswd)
    if ! command -v htpasswd >/dev/null 2>&1; then
        echo -e "${YELLOW}安装 Apache2 Utils (用于 htpasswd)...${NC}"
        apt install -y apache2-utils
    else
        echo -e "${GREEN}Apache2 Utils 已安装${NC}"
    fi
    
    # 检查并安装 SSL 证书工具 (Certbot)
    if ! command -v certbot >/dev/null 2>&1; then
        echo -e "${YELLOW}安装 Certbot (用于 SSL 证书)...${NC}"
        apt install -y certbot python3-certbot-nginx
    else
        echo -e "${GREEN}Certbot 已安装${NC}"
    fi
    
    # 检查 curl 工具
    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${YELLOW}安装 curl...${NC}"
        apt install -y curl
    else
        echo -e "${GREEN}curl 已安装${NC}"
    fi
    
    echo -e "${GREEN}依赖检查完成，所有必要工具已安装${NC}"
}

# 备份 Nginx 配置
backup_nginx_config() {
    echo -e "${YELLOW}备份现有的 Nginx 配置...${NC}"
    
    # 备份主配置文件
    if [ -f "$NGINX_CONF" ]; then
        cp "$NGINX_CONF" "$BACKUP_DIR/nginx.conf.bak"
    fi
    
    # 备份站点配置
    if [ -f "$SITE_CONF" ]; then
        cp "$SITE_CONF" "$BACKUP_DIR/default.bak"
    fi
    
    # 备份密码文件
    if [ -f "$PASSWD_FILE" ]; then
        cp "$PASSWD_FILE" "$BACKUP_DIR/.htpasswd.bak"
    fi
    
    echo -e "${GREEN}Nginx 配置备份完成，备份文件存储在 $BACKUP_DIR${NC}"
}

# 一行输入所有信息
parse_all_inputs() {
    IFS=' ' read -ra INPUTS <<< "$1"
    
    if [ "${#INPUTS[@]}" -lt 3 ]; then
        echo -e "${RED}错误：参数不足。需要至少提供域名、源URL和本地路径${NC}"
        return 1
    fi
    
    DOMAIN="${INPUTS[0]}"
    SOURCE_URL="${INPUTS[1]}"
    LOCAL_PATH="${INPUTS[2]}"
    
    if [ "${#INPUTS[@]}" -gt 3 ]; then
        USERNAME="${INPUTS[3]}"
        if [ "${#INPUTS[@]}" -gt 4 ]; then
            PASSWORD="${INPUTS[4]}"
        else
            USE_DEFAULT_PASSWORD=true
        fi
    else
        USE_DEFAULT_PASSWORD=true
    fi
    
    return 0
}

# 收集转发信息
collect_info() {
    echo -e "${YELLOW}请提供以下信息（你可以在一行中用空格分隔提供所有信息）${NC}"
    echo -e "${YELLOW}格式: 域名 源URL 本地路径 [用户名] [密码]${NC}"
    echo -e "${YELLOW}例如: news.example.com https://source.com/stream/index.m3u8 /live/ admin my_password${NC}"
    read -p "请输入 (或按 Enter 单独填写每一项): " ALL_INPUTS
    
    if [ -n "$ALL_INPUTS" ]; then
        parse_all_inputs "$ALL_INPUTS"
        if [ $? -ne 0 ]; then
            collect_info_separately
        fi
    else
        collect_info_separately
    fi
    
    # 确保源URL和本地路径都以m3u8结尾
    if [[ ! "$SOURCE_URL" =~ \.m3u8$ ]]; then
        echo -e "${RED}错误：源URL必须以 .m3u8 结尾${NC}"
        collect_info
        return
    fi
    
    if [[ ! "$LOCAL_PATH" =~ \.m3u8$ ]]; then
        if [[ "$LOCAL_PATH" =~ /$ ]]; then
            LOCAL_PATH="${LOCAL_PATH}index.m3u8"
        else
            LOCAL_PATH="${LOCAL_PATH}/index.m3u8"
        fi
    fi
    
    # 确保本地路径以/开头
    if [[ ! "$LOCAL_PATH" =~ ^/ ]]; then
        LOCAL_PATH="/$LOCAL_PATH"
    fi
    
    # 提取本地路径的目录部分
    LOCAL_DIR=$(dirname "$LOCAL_PATH")
    
    # 提取源URL的目录和文件名
    SOURCE_DIR=$(dirname "$SOURCE_URL")
    SOURCE_FILE=$(basename "$SOURCE_URL")
    
    echo -e "${GREEN}配置信息已收集完成:${NC}"
    echo -e "域名: ${BLUE}$DOMAIN${NC}"
    echo -e "源URL: ${BLUE}$SOURCE_URL${NC}"
    echo -e "本地路径: ${BLUE}$LOCAL_PATH${NC}"
    echo -e "用户名: ${BLUE}$USERNAME${NC}"
    if [ "$USE_DEFAULT_PASSWORD" = true ]; then
        echo -e "密码: ${BLUE}[使用默认密码]${NC}"
    else
        echo -e "密码: ${BLUE}[已设置]${NC}"
    fi
}

# 逐项收集信息
collect_info_separately() {
    read -p "请输入您的域名 (例如: news.example.com): " DOMAIN
    read -p "请输入M3U8源URL (必须以.m3u8结尾): " SOURCE_URL
    read -p "请输入本地路径 (例如: /live/ 或 /live/index.m3u8): " LOCAL_PATH
    read -p "请输入访问用户名 [默认: admin]: " USERNAME
    USERNAME=${USERNAME:-admin}
    
    read -s -p "请输入访问密码 [直接回车使用默认密码 admin123]: " PASSWORD
    echo ""
    if [ -z "$PASSWORD" ]; then
        PASSWORD="admin123"
        USE_DEFAULT_PASSWORD=true
    fi
}

# 设置 Nginx 密码认证
setup_auth() {
    echo -e "${YELLOW}设置 Nginx 密码认证...${NC}"
    
    # 创建密码文件
    htpasswd -bc "$PASSWD_FILE" "$USERNAME" "$PASSWORD"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}密码认证设置成功${NC}"
    else
        echo -e "${RED}密码认证设置失败${NC}"
        exit 1
    fi
}

# 配置 Nginx
configure_nginx() {
    echo -e "${YELLOW}正在配置 Nginx...${NC}"
    
    # 确保证书目录存在
    DOMAIN_CERT_DIR="$CERT_DIR/$DOMAIN"
    mkdir -p "$DOMAIN_CERT_DIR"
    
    # 提取源URL的主机名
    SOURCE_HOST=$(echo "$SOURCE_URL" | awk -F/ '{print $3}')
    
    # 创建 Nginx 配置文件
    cat > "$NGINX_CONF" << EOL
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	# server_tokens off;

	# server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	##
	# SSL Settings
	##

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;
    log_format auth_log '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent"';
    # -----------------------

    # include /etc/nginx/conf.d/*.conf;
    # include /etc/nginx/sites-enabled/*;

	##
	# Gzip Settings
	##

	gzip on;

	# gzip_vary on;
	# gzip_proxied any;
	# gzip_comp_level 6;
	# gzip_buffers 16 8k;
	# gzip_http_version 1.1;
	# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}


#mail {
#	# See sample authentication script at:
#	# http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#	# auth_http localhost/auth.php;
#	# pop3_capabilities "TOP" "USER";
#	# imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#	server {
#		listen     localhost:110;
#		protocol   pop3;
#		proxy      on;
#	}
#
#	server {
#		listen     localhost:143;
#		protocol   imap;
#		proxy      on;
#	}
#}
EOL

    # 创建站点配置
    cat > "$SITE_CONF" << EOL
# --- HTTPS Server Block for $DOMAIN ---
server {
    listen 443 ssl http2;       # 监听 443 端口 (HTTPS)
    listen [::]:443 ssl http2;   # 监听 IPv6 的 443 端口

    # --- 域名 ---
    server_name $DOMAIN;

    # --- SSL/TLS Certificate Configuration (使用 /root/ 下的路径) ---
    # !! 警告：Nginx 可能因权限不足无法读取这些文件 !!
    ssl_certificate $DOMAIN_CERT_DIR/fullchain.pem;
    ssl_certificate_key $DOMAIN_CERT_DIR/privkey.pem;

    # --- SSL/TLS 安全增强设置 (推荐) ---
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # --- M3U8 Proxy Location with Password and Logging ---
    location $LOCAL_DIR/ { # 访问路径前缀
        # --- Password Protection ---
        auth_basic "Password Protected Stream";
        auth_basic_user_file /etc/nginx/.htpasswd;

        # --- Reverse Proxy Settings ---
        proxy_pass $SOURCE_DIR/; # 源站基础 URL
        proxy_set_header Host $SOURCE_HOST; # 源站 Host 头
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        proxy_redirect off;

        # --- 访问日志记录 ---
        access_log /var/log/nginx/m3u8_auth.log auth_log;
    }

    # (可选) 其他路径处理
    location / {
        return 403 "Forbidden";
    }
}

# --- (推荐) HTTP (80) to HTTPS Redirect ---
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri; # 重定向到 HTTPS
}
EOL

    # 创建符号链接（如果不存在）
    if [ ! -L "$SITE_ENABLED" ]; then
        ln -s "$SITE_CONF" "$SITE_ENABLED"
    fi
    
    echo -e "${GREEN}Nginx 配置完成${NC}"
}

# 申请 SSL 证书
setup_ssl() {
    echo -e "${YELLOW}申请 SSL 证书...${NC}"
    
    # 停止 Nginx 以释放 80 端口
    systemctl stop nginx
    
    # 申请证书
    certbot certonly --standalone --non-interactive --agree-tos --email admin@$DOMAIN -d $DOMAIN
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}SSL 证书申请失败${NC}"
        exit 1
    fi
    
    # 创建证书目录
    DOMAIN_CERT_DIR="$CERT_DIR/$DOMAIN"
    mkdir -p "$DOMAIN_CERT_DIR"
    
    # 复制证书到指定路径
    cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem "$DOMAIN_CERT_DIR/"
    cp /etc/letsencrypt/live/$DOMAIN/privkey.pem "$DOMAIN_CERT_DIR/"
    
    # 修改权限
    chmod 755 "$CERT_DIR"
    chmod 755 "$DOMAIN_CERT_DIR"
    chmod 644 "$DOMAIN_CERT_DIR/fullchain.pem"
    chmod 644 "$DOMAIN_CERT_DIR/privkey.pem"
    
    echo -e "${GREEN}SSL 证书设置完成${NC}"
}

# 设置自动续签
setup_auto_renewal() {
    echo -e "${YELLOW}设置证书自动续签...${NC}"
    
    # 创建续签脚本
    RENEW_SCRIPT="/usr/local/bin/renew_cert_$DOMAIN.sh"
    
    cat > "$RENEW_SCRIPT" << EOL
#!/bin/bash

# 停止 Nginx
systemctl stop nginx

# 续签证书
certbot renew --quiet

# 复制新证书
cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem "$DOMAIN_CERT_DIR/"
cp /etc/letsencrypt/live/$DOMAIN/privkey.pem "$DOMAIN_CERT_DIR/"

# 修改权限
chmod 644 "$DOMAIN_CERT_DIR/fullchain.pem"
chmod 644 "$DOMAIN_CERT_DIR/privkey.pem"

# 启动 Nginx
systemctl start nginx
EOL
    
    chmod +x "$RENEW_SCRIPT"
    
    # 添加定时任务
    (crontab -l 2>/dev/null || echo "") | grep -v "$RENEW_SCRIPT" | { cat; echo "15 3 * * * $RENEW_SCRIPT"; } | crontab -
    
    echo -e "${GREEN}证书自动续签设置完成，每天凌晨3:15执行${NC}"
}

# 启动 Nginx 服务
start_nginx() {
    echo -e "${YELLOW}启动 Nginx 服务...${NC}"
    systemctl start nginx
    systemctl enable nginx
    
    if systemctl is-active nginx >/dev/null; then
        echo -e "${GREEN}Nginx 服务已成功启动${NC}"
    else
        echo -e "${RED}Nginx 服务启动失败，请检查配置${NC}"
        exit 1
    fi
}

# 测试配置
test_configuration() {
    echo -e "${YELLOW}正在测试配置...${NC}"
    
    # 等待服务启动
    sleep 2
    
    # 测试 HTTP 重定向
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN)
    if [ "$HTTP_CODE" -eq 301 ]; then
        echo -e "${GREEN}HTTP 重定向测试通过${NC}"
    else
        echo -e "${RED}HTTP 重定向测试失败，状态码: $HTTP_CODE${NC}"
    fi
    
    # 测试 HTTPS 可用性
    HTTPS_CODE=$(curl -s -k -o /dev/null -w "%{http_code}" https://$DOMAIN)
    if [ "$HTTPS_CODE" -eq 403 ]; then
        echo -e "${GREEN}HTTPS 服务测试通过${NC}"
    else
        echo -e "${RED}HTTPS 服务测试失败，状态码: $HTTPS_CODE${NC}"
    fi
    
    # 提示访问地址和凭据
    echo -e "${GREEN}====================================================${NC}"
    echo -e "${GREEN}M3U8 直播转发已成功部署!${NC}"
    echo -e "${GREEN}直播地址: ${BLUE}https://$DOMAIN$LOCAL_PATH${NC}"
    echo -e "${GREEN}用户名: ${BLUE}$USERNAME${NC}"
    if [ "$USE_DEFAULT_PASSWORD" = true ]; then
        echo -e "${GREEN}密码: ${BLUE}admin123${NC}"
    else
        echo -e "${GREEN}密码: ${BLUE}$PASSWORD${NC}"
    fi
    echo -e "${GREEN}====================================================${NC}"
}

# 恢复原始配置
restore_original_config() {
    echo -e "${YELLOW}正在恢复原始配置...${NC}"
    
    # 停止 Nginx
    systemctl stop nginx
    
    # 恢复配置文件
    if [ -f "$BACKUP_DIR/nginx.conf.bak" ]; then
        cp "$BACKUP_DIR/nginx.conf.bak" "$NGINX_CONF"
    fi
    
    if [ -f "$BACKUP_DIR/default.bak" ]; then
        cp "$BACKUP_DIR/default.bak" "$SITE_CONF"
    fi
    
    if [ -f "$BACKUP_DIR/.htpasswd.bak" ]; then
        cp "$BACKUP_DIR/.htpasswd.bak" "$PASSWD_FILE"
    elif [ -f "$PASSWD_FILE" ]; then
        rm "$PASSWD_FILE"
    fi
    
    # 移除 crontab 任务
    if [ -n "$DOMAIN" ]; then
        (crontab -l 2>/dev/null || echo "") | grep -v "renew_cert_$DOMAIN.sh" | crontab -
        rm -f "/usr/local/bin/renew_cert_$DOMAIN.sh"
    fi
    
    # 启动 Nginx
    systemctl start nginx
    
    echo -e "${GREEN}原始配置已恢复${NC}"
}

# 主函数
main() {
    show_banner
    check_root
    check_dependencies
    
    while true; do
        echo -e "\n${YELLOW}请选择操作:${NC}"
        echo -e "${BLUE}1)${NC} 配置新的 M3U8 直播转发"
        echo -e "${BLUE}2)${NC} 恢复原始配置"
        echo -e "${BLUE}3)${NC} 退出"
        read -p "请输入选项 [1-3]: " CHOICE
        
        case $CHOICE in
            1)
                backup_nginx_config
                collect_info
                setup_auth
                setup_ssl
                configure_nginx
                setup_auto_renewal
                start_nginx
                test_configuration
                break
                ;;
            2)
                restore_original_config
                echo -e "${GREEN}操作完成${NC}"
                break
                ;;
            3)
                echo -e "${GREEN}感谢使用，再见!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选项，请重新选择${NC}"
                ;;
        esac
    done
}

# 执行主函数
main