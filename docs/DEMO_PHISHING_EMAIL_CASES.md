# 钓鱼邮件演示样本集（会议版）

## 使用说明

- 目标：用于现场演示“识别特征 + 风险分 + 证据链”。
- 建议：每次演示时固定输入 1 条高风险 + 1 条中风险 + 1 条正常邮件，便于对比。
- 注意：以下样本均为演示文本，已去除真实敏感信息。

---

## 样本 1：假冒银行账户冻结（高风险）

- 类型：凭证窃取 / 链接钓鱼
- 主题：`【紧急】您的银行账户存在异常，请立即验证`
- 发件人：`security@bankofchina-verify.com`
- 正文：

```text
尊敬的用户：

我们检测到您的账户存在异常登录行为。为保护您的资金安全，请在24小时内点击以下链接完成身份验证：

http://192.168.1.100:8080/verify?id=user123

如未在24小时内完成验证，您的账户将被临时冻结。

中国银行安全中心
```

- 预期信号：
  - urgency / credential_request
  - 可疑 URL（IP + 异常端口）
  - 风险分应明显偏高

---

## 样本 2：CEO 转账指令（高风险）

- 类型：BEC 商务邮件欺诈
- 主题：`关于紧急资金调拨的机密指示`
- 发件人：`ceo.wang@company.com`
- 正文：

```text
张总：

我正在参加一个机密的投资方会议，需要立即完成一笔资金调拨。这是我们与红杉资本合作项目的预付款，金额为 48 万欧元。

请将款项转入以下账户（对方财务已确认）：
开户行：德意志银行法兰克福分行
IBAN：DE89 3704 0044 0532 0130 00
户名：Sequoia Capital Partners GmbH

这是高度机密项目，请勿向其他人透露。我会议结束后会详细解释。

王总
```

- 预期信号：
  - authority / secrecy / financial_request
  - 行为异常与社工话术并发
  - 风险等级至少应为中高风险

---

## 样本 3：Microsoft 账号验证（高风险）

- 类型：品牌仿冒 + 凭证窃取
- 主题：`Action Required: Verify Your Microsoft 365 Account`
- 发件人：`noreply@mircosoft-security.com`
- 正文：

```text
Dear User,

We have detected unusual sign-in activity on your Microsoft 365 account from an unrecognized device.

To secure your account, please verify your identity immediately by clicking the link below:

https://login.mircosoft-verify.com/@secure-login/validate

If you do not verify within 24 hours, your account will be suspended.

Microsoft Security Team
```

- 预期信号：
  - 域名拼写仿冒（mircosoft）
  - credential_request / urgency
  - URL reputation 或行为证据命中

---

## 样本 4：付款单据附件诱导（中风险）

- 类型：附件诱导 / 财务欺诈前置话术
- 主题：`付款单据请查收`
- 发件人：`finance@support-verify.xyz`
- 正文：

```text
请在附件查看付款单据，双击后请勿打开外部链接。
```

- 预期信号：
  - possible_attachment_scam
  - behavior_anomaly（financial_request）
  - 风险等级应至少为 low/medium，不应直接 safe

---

## 样本 5：正常团队周报（安全对照）

- 类型：正常业务邮件
- 主题：`本周工作总结和下周计划`
- 发件人：`li.ming@company.com`
- 正文：

```text
Hi all,

以下是本周的工作总结和下周计划：

本周完成：
1. 完成了用户认证模块的重构
2. 修复了3个线上bug
3. 参加了客户需求评审会议

下周计划：
1. 开始新功能的开发
2. 准备版本发布的测试用例

如有问题请随时沟通。

李明
```

- 预期信号：
  - 不应出现明显高危标记
  - 风险分应较低
  - 作为演示中的反例基准

---

## 现场演示建议流程（5 分钟）

1. 先输入样本 5（正常邮件），展示低风险结果。
2. 输入样本 1（银行冻结），展示高风险与证据链。
3. 输入样本 4（附件诱导），展示“非链接型风险”也可识别。
4. 对比 `content_flags` 与 `evidence_items` 的差异，解释“为什么判定不同”。

---

## 快速检查项

- 报告是否显示 `risk_level` 与 `risk_score`
- 是否能看到 `content_flags`
- 是否能看到 `evidence_items`（至少包含 semantic / detection / risk）
- 正常样本与钓鱼样本是否拉开分差
