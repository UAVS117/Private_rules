# 1. 安装 vnStat (如果没装)
apt-get update && apt-get install -y vnstat bc iptables-persistent 2>/dev/null || yum install -y vnstat bc iptables-services

# 2. 写入自动流量限制脚本
cat << 'EOF' > /usr/local/bin/limit_daily_traffic.sh
#!/bin/bash
# ==========================================
# 每日出站流量限制脚本 (GCP 200G 薅羊毛专用)
# 设定: 每天 6GB 出站流量上限
# 动作: 超过则断网，次日 0点 自动恢复
# ==========================================

LIMIT_GB=6
# 获取今日出站流量 (TX) 单位: GB
# vnstat json output -> jq parsing is better but dependency heavy. 
# Using raw output parsing for compatibility.
# vnstat --oneline format: 
# v5: date;rx;tx;...
TODAY_TX=$(vnstat -d --oneline | awk -F';' '{print $6}' | sed 's/ GiB//g' | sed 's/ MiB//g' | sed 's/ KiB//g')

# 单位换算检查 (vnstat 输出可能是 MiB 或 KiB)
UNIT=$(vnstat -d --oneline | awk -F';' '{print $6}' | grep -o '[GMK]iB')

if [[ "$UNIT" == "MiB" ]]; then
    # 转换为 GB
    TODAY_TX=$(echo "scale=4; $TODAY_TX / 1024" | bc)
elif [[ "$UNIT" == "KiB" ]]; then
    TODAY_TX=$(echo "scale=4; $TODAY_TX / 1024 / 1024" | bc)
fi

echo "$(date): Today TX: ${TODAY_TX} GB / Limit: ${LIMIT_GB} GB"

# 判断是否超标
if (( $(echo "$TODAY_TX > $LIMIT_GB" | bc -l) )); then
    echo "Traffic exceeded. Blocking output traffic..."
    # 添加 iptables 规则阻断出站流量 (保留 SSH 端口 22/20202 防止失联)
    iptables -C OUTPUT -p tcp --sport 20202 -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p tcp --sport 20202 -j ACCEPT
    iptables -C OUTPUT -p tcp --sport 22 -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
    
    # 阻断其他所有出站流量 (TCP/UDP)
    iptables -C OUTPUT -j DROP 2>/dev/null || iptables -A OUTPUT -j DROP
    
    echo "Blocked."
else
    # 未超标，确保没有阻断规则
    # 检查是否存在 DROP 规则，有则清除
    if iptables -C OUTPUT -j DROP 2>/dev/null; then
        echo "Traffic within limit. Unblocking..."
        # 清除所有 OUTPUT 规则 (简单粗暴但有效，或者只删 DROP)
        # 为安全起见，我们只删除特定的 DROP 规则
        iptables -D OUTPUT -j DROP
        echo "Unblocked."
    fi
fi
EOF

# 3. 赋予执行权限
chmod +x /usr/local/bin/limit_daily_traffic.sh

# 4. 设置定时任务 (每5分钟检测一次)
(crontab -l 2>/dev/null | grep -v "limit_daily_traffic.sh"; echo "*/5 * * * * /usr/local/bin/limit_daily_traffic.sh") | crontab -

echo "部署完成！每日出站流量超过 6GB 将自动切断网络 (保留 SSH)，次日自动恢复。"
