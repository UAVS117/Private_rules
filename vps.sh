cat << 'EOF' > /usr/local/bin/vps && chmod +x /usr/local/bin/vps
#!/bin/bash

# ====================================================
# 脚本名称: vps (E-Way Pilot 旗舰交版 v3.3 blog.oool.cc)
# 功能: 运维部署(1-6) + 结果验收探针(7)
# 更新日志 v3.3:
#   1. 恢复区域检测逻辑，优化 XanMod 镜像连接策略
#   2. 修复 AWS Ubuntu Root 登录被 cloud-init 覆盖问题
#   3. 修复 Ubuntu GPG 目录缺失导致的 403/写入失败问题
# ====================================================

# --- 颜色与样式 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
SKYBLUE='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

[[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须以 root 权限运行!${NC}" && exit 1
STATE_FILE="/etc/vps_script_state"
XANMOD_KEY_FINGERPRINT="86F7D09EE734E623"

# ====================================================
#   基础工具与环境预处理
# ====================================================

function check_dependencies() {
    # 修复 Ubuntu GPG 目录缺失问题 (关键修复)
    if [ ! -d "/root/.gnupg" ]; then
        echo -e "${YELLOW}检测到 GPG 目录缺失，正在初始化环境...${NC}"
        mkdir -p -m 700 /root/.gnupg
    else
        chmod 700 /root/.gnupg
    fi

    # 兼容性安装依赖
    if ! command -v wget >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
        echo -e "${YELLOW}正在安装基础工具 (curl/wget/gpg)...${NC}"
        apt-get update -qq 
        apt-get install -y -qq wget curl gnupg gnupg2 dirmngr ca-certificates
    fi
}

# 获取地理位置并优化连接 (恢复原逻辑)
function check_region() {
    echo -e "${YELLOW}正在检测 VPS 地理位置以优化连接...${NC}"
    # 使用 ip-api 检测，超时自动跳过
    region_data=$(curl -s --connect-timeout 3 http://ip-api.com/json)
    country=$(echo "$region_data" | grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4)
    
    if [[ "$country" == "CN" ]] || [[ "$country" == "HK" ]] || [[ "$country" == "TW" ]] || [[ "$country" == "SG" ]] || [[ "$country" == "JP" ]]; then
        echo -e "${GREEN}检测到亚太地区 ($country)，将尝试优化连接策略。${NC}"
        REGION_OPT="ASIA"
    elif [[ "$country" == "US" ]] || [[ "$country" == "CA" ]]; then
        echo -e "${GREEN}检测到北美地区 ($country)，使用默认源。${NC}"
        REGION_OPT="NA"
    else
        echo -e "${GREEN}检测到区域 ($country)，使用全球加速源。${NC}"
        REGION_OPT="GLOBAL"
    fi
}

# ====================================================
#   核心功能模块
# ====================================================

# 清理旧 BBR 配置
function clean_bbr_configs() {
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    rm -f /etc/sysctl.d/99-bbr.conf
    rm -f /etc/sysctl.d/99-xanmod-bbr.conf
}

# 重启后自动恢复逻辑
function check_resume_state() {
    if [ -f $STATE_FILE ]; then
        clear
        echo -e "${SKYBLUE}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${SKYBLUE}║      系统重启检测完毕，正在执行 BBR3 激活        ║${NC}"
        echo -e "${SKYBLUE}╚══════════════════════════════════════════════════╝${NC}"
        
        current_kernel=$(uname -r)
        if echo "$current_kernel" | grep -qi "xanmod"; then
            echo -e "${GREEN}当前内核: $current_kernel (验证通过)${NC}"
            clean_bbr_configs
            
            # 尝试激活 fq_pie (XanMod 推荐)
            echo "net.core.default_qdisc=fq_pie" > /etc/sysctl.d/99-xanmod-bbr.conf
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-xanmod-bbr.conf
            
            modprobe tcp_bbr 2>/dev/null
            
            # 如果不支持 fq_pie，降级为 fq
            if ! sysctl -p /etc/sysctl.d/99-xanmod-bbr.conf >/dev/null 2>&1; then
                echo -e "${YELLOW}提示: 环境不支持 fq_pie，自动降级为 fq...${NC}"
                echo "net.core.default_qdisc=fq" > /etc/sysctl.d/99-xanmod-bbr.conf
                echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-xanmod-bbr.conf
                sysctl -p /etc/sysctl.d/99-xanmod-bbr.conf >/dev/null 2>&1
            fi
            
            rm -f $STATE_FILE
            echo -e "${GREEN}BBRv3 激活成功！${NC}"
            # 自动进入探针以验收结果
            echo -e "${YELLOW}即将自动运行探针以验收安装结果...${NC}"
            sleep 2
            run_probe
            return
        else
            echo -e "${RED}内核切换失败，当前仍为: $current_kernel${NC}"
            rm -f $STATE_FILE 
        fi
    fi
}

# 1. SSH 配置 (AWS Ubuntu 深度修复版)
function setup_ssh() {
    echo -e "${YELLOW}正在配置 Root 密码登录...${NC}"
    read -p "请输入要设置的 root 密码: " root_pass
    echo "root:$root_pass" | chpasswd
    
    SSH_CONF="/etc/ssh/sshd_config"
    
    # 备份
    cp $SSH_CONF "${SSH_CONF}.bak"
    
    # [关键修复] Ubuntu/AWS 必须处理 Include 导致的配置覆盖
    # 方法1: 注释掉 Include 行 (最稳妥)
    sed -i 's/^Include /#Include /g' $SSH_CONF
    
    # 方法2: 如果 sshd_config.d 存在，强制重命名其中的 cloud-init 配置文件使其失效
    if [ -d "/etc/ssh/sshd_config.d" ]; then
        for f in /etc/ssh/sshd_config.d/*.conf; do
            [ -e "$f" ] && mv "$f" "${f}.disabled" 2>/dev/null
        done
    fi

    # 清理并写入主配置
    sed -i '/^PermitRootLogin/d' $SSH_CONF
    sed -i '/^PasswordAuthentication/d' $SSH_CONF
    
    echo "PermitRootLogin yes" >> $SSH_CONF
    echo "PasswordAuthentication yes" >> $SSH_CONF
    
    # 兼容性重启服务
    if systemctl list-unit-files | grep -q sshd.service; then
        systemctl restart sshd
    else
        systemctl restart ssh
    fi
    
    echo -e "${GREEN}SSH 配置完成！${NC}"
    echo -e "${SKYBLUE}注意: 请确保云服务商防火墙(安全组)已放行 22 端口。${NC}"
}

# 2. Swap 配置
function setup_swap() {
    echo -e "${YELLOW}正在配置虚拟内存 Swap...${NC}"
    if grep -q "swap" /etc/fstab; then
        swapoff -a
        sed -i '/swap/d' /etc/fstab
        rm -f /swapfile
    fi
    read -p "请输入 Swap 大小 (单位G，默认2G): " swap_size
    swap_size=${swap_size:-2}
    fallocate -l "${swap_size}G" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=$((swap_size * 1024)) status=progress
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo 'vm.swappiness=10' > /etc/sysctl.d/99-swap.conf
    sysctl -p /etc/sysctl.d/99-swap.conf
    echo -e "${GREEN}Swap ${swap_size}G 配置成功！${NC}"
}

# 3. 标准 BBR
function enable_bbr() {
    echo -e "${YELLOW}正在开启标准 BBR...${NC}"
    clean_bbr_configs
    echo "net.core.default_qdisc=fq" > /etc/sysctl.d/99-bbr.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-bbr.conf
    sysctl --system
    echo -e "${GREEN}标准 BBR 已开启！${NC}"
}

# 4. XanMod + BBR3 (全平台兼容 + 逻辑修复版)
function setup_xanmod() {
    echo -e "${YELLOW}正在优化 initramfs (防爆盘)...${NC}"
    if [ -f /etc/initramfs-tools/initramfs.conf ]; then
        sed -i 's/^MODULES=.*/MODULES=dep/' /etc/initramfs-tools/initramfs.conf
        sed -i 's/^COMPRESS=.*/COMPRESS=gzip/' /etc/initramfs-tools/initramfs.conf
    fi

    check_dependencies
    check_region # 调用区域检测

    echo -e "${YELLOW}正在获取 GPG 密钥...${NC}"
    mkdir -p /etc/apt/keyrings
    rm -f /etc/apt/keyrings/xanmod-archive-keyring.gpg
    
    # 模拟浏览器 User-Agent (解决 403 错误的核心)
    UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    # 根据区域选择策略 (恢复逻辑)
    # 虽然 XanMod 官方推荐 dl.xanmod.org，但我们通过 UA 伪装和重试机制确保连接
    # 如果未来有特定亚洲源，可在此处扩展 CASE 逻辑
    
    KEY_URL="https://dl.xanmod.org/archive.key"
    
    echo -e "${SKYBLUE}正在尝试从官方源下载密钥 (Region: ${REGION_OPT})...${NC}"
    
    # 尝试下载
    if curl -A "$UA" -fsSL "$KEY_URL" -o /tmp/xanmod.key; then
        echo -e "${GREEN}[OK] 密钥下载成功${NC}"
    else
        echo -e "${RED}[Error] 官方源连接失败 (403/Timeout)，尝试使用 Keyserver 回退方案...${NC}"
        # 回退方案：使用 Keyserver
        if ! gpg --no-default-keyring --keyring /etc/apt/keyrings/xanmod-archive-keyring.gpg --keyserver keyserver.ubuntu.com --recv-keys $XANMOD_KEY_FINGERPRINT; then
             echo -e "${RED}密钥获取彻底失败，请检查网络连接。${NC}"
             rm -f /tmp/xanmod.key
             return
        else
             echo -e "${GREEN}[OK] 通过 Keyserver 获取成功${NC}"
             # 跳过后续导入，直接去写源
             goto_repo_setup=true
        fi
    fi

    # 导入密钥 (如果是 curl 下载的)
    if [ "$goto_repo_setup" != "true" ]; then
        # 修复：Ubuntu 下 gpg 可能因为 .gnupg 权限问题报错，这里再次强制处理
        chmod 700 /root/.gnupg 2>/dev/null
        
        gpg --dearmor --yes -o /etc/apt/keyrings/xanmod-archive-keyring.gpg /tmp/xanmod.key
        if [ -s /etc/apt/keyrings/xanmod-archive-keyring.gpg ]; then
            echo -e "${GREEN}[OK] 密钥导入成功${NC}"
        else
            echo -e "${RED}密钥转换失败 (GPG Error)，请截图反馈。${NC}"
            rm -f /tmp/xanmod.key
            return
        fi
        rm -f /tmp/xanmod.key
    fi

    # 写入软件源
    echo 'deb [signed-by=/etc/apt/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' > /etc/apt/sources.list.d/xanmod-release.list

    echo -e "${YELLOW}正在安装 XanMod 内核...${NC}"
    apt-get update
    
    # 智能选择安装版本
    # 修复: 检测 CPU 是否支持 x64v3 (AVX2, FMA, BMI2, MOVBE)
    # 如果不支持，降级到 x64v1 (通用兼容版) 以防止老旧 CPU 无法启动
    cpu_flags=$(grep -m1 'flags' /proc/cpuinfo)
    if echo "$cpu_flags" | grep -q 'avx2' && echo "$cpu_flags" | grep -q 'fma' && echo "$cpu_flags" | grep -q 'bmi2' && echo "$cpu_flags" | grep -q 'movbe'; then
        echo -e "${GREEN}检测到现代 CPU，将安装高性能版 (x64v3)...${NC}"
        target_kernel="linux-xanmod-x64v3"
    else
        echo -e "${YELLOW}检测到老旧或基础 CPU，将安装通用兼容版 (x64v1)...${NC}"
        target_kernel="linux-xanmod-x64v1"
    fi
    
    if apt-get install "$target_kernel" -y; then
        echo "XANMOD_PENDING_REBOOT" > $STATE_FILE
        echo -e "${GREEN}内核安装成功！${NC}"
        read -p "必须重启以生效。重启后脚本会自动完成 BBR3 配置。是否立即重启? (y/n): " res
        [[ "$res" == "y" ]] && reboot
    else
        echo -e "${RED}安装失败，正在尝试自动修复依赖...${NC}"
        apt-get install -f -y
        if apt-get install "$target_kernel" -y; then
             echo "XANMOD_PENDING_REBOOT" > $STATE_FILE
             read -p "安装成功，是否立即重启? (y/n): " res
             [[ "$res" == "y" ]] && reboot
        else
             echo -e "${RED}XanMod 安装彻底失败。可能原因：系统版本过旧或网络无法连接仓库。${NC}"
        fi
    fi
}

# 6. 卸载
function uninstall_script() {
    echo -e "${RED}正在卸载...${NC}"
    swapoff -a 2>/dev/null
    sed -i '/swap/d' /etc/fstab
    rm -f /swapfile
    rm -f /etc/sysctl.d/99-swap.conf
    clean_bbr_configs
    rm -f /etc/apt/sources.list.d/xanmod-release.list
    rm -f /etc/apt/keyrings/xanmod-archive-keyring.gpg
    rm -f /usr/local/bin/vps
    rm -f $STATE_FILE
    # 恢复 SSH 配置 (仅取消 Include 的注释，不回滚密码策略以免失联)
    sed -i 's/^#Include /Include /g' /etc/ssh/sshd_config
    echo -e "${GREEN}脚本已彻底卸载。${NC}"
    exit 0
}

# ====================================================
#   模块 7: VPS 验收探针 (结果驻留版)
# ====================================================
function run_probe() {
    # 依赖检查
    if ! command -v traceroute >/dev/null 2>&1; then 
        echo -e "${YELLOW}正在安装探针依赖...${NC}"
        apt-get update -qq && apt-get install traceroute netcat-openbsd -y -qq
    fi
    
    clear
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${SKYBLUE}         VPS 部署验收探针 (E-Way Pilot 交付版) blog.oool.cc       ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"

    # --- 1. 验证系统与内核 ---
    kernel=$(uname -r)
    cpu_cores=$(grep -c 'processor' /proc/cpuinfo)
    mem=$(free -m | awk '/Mem:/ {print $3 "/" $2 " MB"}')
    disk=$(df -h / | awk 'NR==2 {print $3 "/" $2}')

    # --- 2. 验证 Swap ---
    swap_total=$(free -m | awk '/Swap:/ {print $2}')
    if [ "$swap_total" -gt 0 ]; then
        swap_used=$(free -m | awk '/Swap:/ {print $3}')
        swap_status="${GREEN}已开启${NC} ($swap_used/$swap_total MB)"
    else
        swap_status="${RED}未开启${NC}"
    fi

    # --- 3. 验证 BBR ---
    tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    if [[ "$tcp_cc" == *"bbr"* ]]; then
        if [[ "$kernel" == *"xanmod"* ]]; then 
            bbr_ver="BBRv3 (XanMod + $qdisc)"
        elif [[ $(modinfo tcp_bbr 2>/dev/null) == *"version: 3"* ]]; then 
            bbr_ver="BBRv3"
        else 
            bbr_ver="BBR 标准版"
        fi
        bbr_status="${GREEN}已开启${NC} ${SKYBLUE}[$bbr_ver]${NC}"
    else
        bbr_status="${RED}未开启${NC} ($tcp_cc)"
    fi

    echo -e "${YELLOW}[系统验收]${NC}"
    echo -e "核心: $kernel | CPU: ${cpu_cores}核"
    echo -e "配置: 内存 $mem | 硬盘 $disk"
    echo -e "Swap: $swap_status"
    echo -e "BBR : $bbr_status"

    # --- 4. 验证网络与 IPv6 ---
    echo -e "\n${YELLOW}[网络质量分析]${NC}"
    ip_info=$(curl -s --connect-timeout 5 http://ip-api.com/json?fields=query,isp,country,proxy,hosting)
    ip=$(echo "$ip_info" | grep -o '"query":"[^"]*"' | cut -d'"' -f4)
    isp=$(echo "$ip_info" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
    country=$(echo "$ip_info" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
    
    # 风险检测
    if echo "$ip_info" | grep -q '"proxy":true'; then type="${RED}代理IP${NC}";
    elif echo "$ip_info" | grep -q '"hosting":true'; then type="${YELLOW}数据中心IP${NC}";
    else type="${GREEN}原生IP${NC}"; fi

    # IPv6 深度检测
    ipv6=$(curl -6 -s --max-time 2 ipv6.ip.sb)
    if [ -z "$ipv6" ]; then ipv6=$(curl -6 -s --max-time 2 api6.ipify.org); fi
    if [ -n "$ipv6" ]; then ipv6_disp="${GREEN}已连接${NC}"; else ipv6_disp="${RED}未检测到${NC}"; fi

    echo -e "IPv4: $ip ($country - $isp) | 类型: $type"
    echo -e "IPv6: $ipv6_disp"

    # --- 5. 验证解锁 (含 Gemini) ---
    echo -e "\n${YELLOW}[流媒体与AI解锁]${NC}"
    UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    check() {
        code=$(curl -sL -m 3 -o /dev/null -w "%{http_code}" -A "$UA" "$1")
        if [[ "$code" == "200" || "$code" == "302" ]]; then echo -e "$2: ${GREEN}Yes${NC}"; else echo -e "$2: ${RED}No${NC}"; fi
    }
    # 并行检测提升速度
    check "https://gemini.google.com/app" "Gemini " &
    {
        # ChatGPT 专用检测: 优先 iOS 接口 -> API 401 验证
        c_code=$(curl -sL -m 5 -o /dev/null -w "%{http_code}" -A "$UA" "https://ios.chat.openai.com/public-api/mobile/server_status/v1")
        if [[ "$c_code" == "200" ]]; then
            echo -e "ChatGPT: ${GREEN}Yes${NC}"
        else
            c_code=$(curl -sL -m 5 -o /dev/null -w "%{http_code}" -A "$UA" -H "Authorization: Bearer null" "https://api.openai.com/v1/models")
            if [[ "$c_code" == "401" || "$c_code" == "429" ]]; then echo -e "ChatGPT: ${GREEN}Yes${NC}"; else echo -e "ChatGPT: ${RED}No${NC}"; fi
        fi
    } &
    {
        # Claude 2 深度检测 (API 400/401/429 或 网页伪装)
        # 策略: 优先测 API (低风控)，若被盾(403)则测网页(高伪装)
        # API: 发送 POST 请求，若返回 400(Bad Request) 或 401(Unauthorized) 说明已过地区锁
        c_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -m 5 -A "$UA" \
            -H "x-api-key: invalid" -H "anthropic-version: 2023-06-01" \
            "https://api.anthropic.com/v1/messages")
            
        if [[ "$c_code" == "400" || "$c_code" == "401" || "$c_code" == "429" ]]; then
            echo -e "Claude 2: ${GREEN}Yes${NC}"
        else
            # 网页: 模拟真实浏览器头信息访问登录页
            c_code=$(curl -s -o /dev/null -w "%{http_code}" -m 6 \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
                -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
                -H "Accept-Language: en-US,en;q=0.9" \
                "https://claude.ai/login")
            if [[ "$c_code" == "200" || "$c_code" =~ ^3 ]]; then
                echo -e "Claude 2: ${GREEN}Yes${NC}"
            else
                echo -e "Claude 2: ${RED}No${NC}"
            fi
        fi
    } &
    check "https://www.youtube.com/" "YouTube" &
    check "https://www.tiktok.com/" "TikTok" &
    check "https://www.netflix.com/title/80018499" "Netflix" &

    wait
    echo "" 

    # --- 6. 验证路由 ---
    echo -e "${YELLOW}[回程线路简报]${NC}"
    run_trace() {
        # 只取第一跳有意义的骨干网IP判断
        t=$(traceroute -I -q 1 -n -m 30 $1 | grep -v "* * *" | grep -E "59.43|202.97|219.158|4837|9929|221.183|223.5" -m 1)
        if echo "$t" | grep -q "59.43"; then type="${PURPLE}CN2 GIA${NC}"; 
        elif echo "$t" | grep -q "4837"; then type="${SKYBLUE}CU 4837${NC}"; 
        elif echo "$t" | grep -q "9929"; then type="${PURPLE}CU 9929${NC}"; 
        elif echo "$t" | grep -q "221.183"; then type="${YELLOW}CMI${NC}"; 
        else type="普通线路"; fi
        echo -e "$2: $type"
    }
    run_trace "113.108.81.36" "电信" &
    run_trace "210.21.196.6"  "联通" &
    run_trace "120.196.165.24" "移动" &
    wait

    echo -e "\n${GREEN}验收完成。上方结果已保留，请在下方选择后续操作：${NC}"
    main_menu "keep_screen"
}

function main_menu() {
    # 每次回菜单检查环境
    check_dependencies
    
    if [ "$1" != "keep_screen" ]; then
        check_resume_state
        clear
    fi
    
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${SKYBLUE}            E-Way Pilot 自动化运维脚本旗舰版 (blog.oool.cc)       ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "1) GCP, AWS VPS root用户远程ssh登录 (含AWS修复)"
    echo -e "2) 建立虚拟内存 Swap (可自定义大小)"
    echo -e "3) 开启标准 BBR"
    echo -e "4) 安装 XanMod 内核开启 BBR3 (含区域优化+403修复)"
    echo -e "5) 以上 1-4 选项全选"
    echo -e "6) 卸载本脚本"
    echo -e "${YELLOW}7) 运行探针 (验收安装结果 / 检查 Gemini & IPv6)${NC}"
    echo -e "0) 退出"
    echo -e "${GREEN}────────────────────────────────────────────────────────────────────${NC}"
    read -p "请选择操作 [0-7]: " choice
    case $choice in
        1) setup_ssh; main_menu ;;
        2) setup_swap; main_menu ;;
        3) enable_bbr; main_menu ;;
        4) setup_xanmod ;; 
        5) setup_ssh; setup_swap; enable_bbr; setup_xanmod ;;
        6) uninstall_script ;;
        7) run_probe ;;
        0) exit 0 ;;
        *) main_menu ;;
    esac
}

main_menu
EOF
