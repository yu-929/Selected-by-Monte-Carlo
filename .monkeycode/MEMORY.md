# User Instruction Memory

## Format

### User Instruction Entry
[User Instruction Summary]
- Date: [YYYY-MM-DD]
- Context: [Mentioned scenario or time]
- Instructions:
  - [Content of user teaching or instruction, described line by line]

## Entries

[保持三阶段扫描而非简化]
- Date: 2026-08-04
- Context: 上游 zjh327954/123 将 check_cf_asn.py 简化为单阶段 TLS 扫描，移除 HTTP 301 校验和自定义域名校验
- Instructions:
  - 不同步上游简化方案，保持现有三阶段扫描（TLS 粗筛 → HTTP 301 校验 → 自定义域名校验）
  - 理由：validate.py 做最终 API 验证，三阶段预过滤减少无效 IP 进入验证阶段，节省 API 配额、降低虚报率
  - 上游单阶段 TLS 方案虚报率更高，不适合本项目的验证流程