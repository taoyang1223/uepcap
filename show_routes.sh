#!/bin/bash

# 脚本：显示所有IPv4/IPv6路由表和策略路由表
# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_subheader() {
    echo -e "\n${YELLOW}--- $1 ---${NC}"
}

# 获取所有路由表名称
get_route_tables() {
    if [ -f /etc/iproute2/rt_tables ]; then
        grep -v '^#' /etc/iproute2/rt_tables | grep -v '^$' | awk '{print $2}'
    fi
}

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║        Linux 路由表和策略路由完整信息                        ║${NC}"
echo -e "${CYAN}║        $(date '+%Y-%m-%d %H:%M:%S')                                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

# ==================== IPv4 部分 ====================
print_header "IPv4 策略路由规则 (ip rule list)"
ip -4 rule list 2>/dev/null || echo "无法获取IPv4策略路由规则"

print_header "IPv4 主路由表 (ip route show table main)"
ip -4 route show table main 2>/dev/null || echo "无法获取IPv4主路由表"

print_header "IPv4 本地路由表 (ip route show table local)"
ip -4 route show table local 2>/dev/null || echo "无法获取IPv4本地路由表"

print_header "IPv4 默认路由表 (ip route show table default)"
ip -4 route show table default 2>/dev/null || echo "无法获取IPv4默认路由表"

# 显示所有自定义路由表
print_header "IPv4 所有路由表汇总"
for table in $(get_route_tables); do
    routes=$(ip -4 route show table "$table" 2>/dev/null)
    if [ -n "$routes" ]; then
        print_subheader "表: $table"
        echo "$routes"
    fi
done

# 显示所有IPv4路由（简洁方式）
print_header "IPv4 完整路由表 (ip route show table all)"
ip -4 route show table all 2>/dev/null | head -200
route_count=$(ip -4 route show table all 2>/dev/null | wc -l)
if [ "$route_count" -gt 200 ]; then
    echo -e "${YELLOW}... (共 $route_count 条路由，仅显示前200条)${NC}"
fi

# ==================== IPv6 部分 ====================
print_header "IPv6 策略路由规则 (ip -6 rule list)"
ip -6 rule list 2>/dev/null || echo "无法获取IPv6策略路由规则"

print_header "IPv6 主路由表 (ip -6 route show table main)"
ip -6 route show table main 2>/dev/null || echo "无法获取IPv6主路由表"

print_header "IPv6 本地路由表 (ip -6 route show table local)"
ip -6 route show table local 2>/dev/null || echo "无法获取IPv6本地路由表"

print_header "IPv6 默认路由表 (ip -6 route show table default)"
ip -6 route show table default 2>/dev/null || echo "无法获取IPv6默认路由表"

# 显示所有自定义路由表
print_header "IPv6 所有路由表汇总"
for table in $(get_route_tables); do
    routes=$(ip -6 route show table "$table" 2>/dev/null)
    if [ -n "$routes" ]; then
        print_subheader "表: $table"
        echo "$routes"
    fi
done

# 显示所有IPv6路由（简洁方式）
print_header "IPv6 完整路由表 (ip -6 route show table all)"
ip -6 route show table all 2>/dev/null | head -200
route_count=$(ip -6 route show table all 2>/dev/null | wc -l)
if [ "$route_count" -gt 200 ]; then
    echo -e "${YELLOW}... (共 $route_count 条路由，仅显示前200条)${NC}"
fi

# ==================== 路由表定义 ====================
print_header "路由表定义 (/etc/iproute2/rt_tables)"
if [ -f /etc/iproute2/rt_tables ]; then
    cat /etc/iproute2/rt_tables
else
    echo "文件不存在"
fi

# ==================== 网络接口信息 ====================
print_header "网络接口概览"
ip -br addr 2>/dev/null || ip addr show

# ==================== 统计信息 ====================
print_header "统计摘要"
echo -e "IPv4 路由总数: ${GREEN}$(ip -4 route show table all 2>/dev/null | wc -l)${NC}"
echo -e "IPv6 路由总数: ${GREEN}$(ip -6 route show table all 2>/dev/null | wc -l)${NC}"
echo -e "IPv4 策略规则: ${GREEN}$(ip -4 rule list 2>/dev/null | wc -l)${NC}"
echo -e "IPv6 策略规则: ${GREEN}$(ip -6 rule list 2>/dev/null | wc -l)${NC}"

echo -e "\n${CYAN}脚本执行完毕${NC}\n"

