# service-mesh-egress-route-conflict-analyzer
分析出口网关、SNI、通配域名和路由覆盖冲突

## 功能

`egress_analyzer.py` 对出口网关的**静态配置**做离线分析，不接触运行中的网格、
不抓取实时流量。输入是一组有序路由规则（FQDN/通配域名、端口、协议、来源工作负载
标签、TLS 校验策略），输出：

- 每个候选域名最终命中的路由（首条匹配规则生效）
- 被通配规则遮蔽的精确规则
- SNI 与 Host 不一致时的冲突说明（PASSTHROUGH 按 SNI 路由，SIMPLE/MUTUAL 按 Host 路由）
- 建议的规则调整顺序（精确优先于通配，端口/协议/工作负载越具体越靠前）

匹配语义：域名大小写不敏感；`*.example.com` 匹配任意子域但不匹配 `example.com`
本身；端口、协议、来源工作负载为 `None` 时表示任意。

## 使用

```bash
python egress_analyzer.py   # 运行内置示例
python -m unittest          # 运行测试（Python 3.8.2）
```
