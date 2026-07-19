# AI 钓鱼邮件智能检测系统 (PhishingDetector)

基于多 Agent 协作的钓鱼邮件智能检测系统，使用 LangGraph 编排 4 个专业 Agent，结合 Minimax M3 大语言模型和规则引擎，实现从语义分析到自主响应的全自动检测闭环。

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    LangGraph 工作流状态机                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │  Agent #1    │    │  Agent #2    │    │  Agent #3    │       │
│  │ 语义意图分析 │───▶│ 多维关联检测 │───▶│  风险研判    │       │
│  │              │    │              │    │              │       │
│  │ • LLM语义分析│    │ • 规则引擎   │    │ • 综合评分   │       │
│  │ • 社会工程   │    │ • LLM深度分析│    │ • ATT&CK映射 │       │
│  │   话术识别   │    │ • 分数融合   │    │ • 风险等级   │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                    │              │
│                                                    ▼              │
│                                            ┌──────────────┐     │
│                                            │  Agent #4    │     │
│                                            │  自主响应    │     │
│                                            │              │     │
│                                            │ • 处置决策   │     │
│                                            │ • 告警生成   │     │
│                                            │ • 溯源报告   │     │
│                                            └──────────────┘     │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         数据持久化层                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  FastAPI     │  │  SQLite DB   │  │  Gradio UI   │          │
│  │  REST API    │  │  邮件+报告   │  │  Web 界面    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

## 项目结构

```
Phishing_detector/
├── .env.example              # 环境变量模板
├── .gitignore
├── README.md                 # 项目说明文档
├── TECH.md                   # 技术设计文档
├── requirements.txt          # Python 依赖
├── main.py                   # 主入口（支持多种启动模式）
├── data/                     # 数据集目录（不上传 GitHub）
│   ├── raw/                  # 原始数据集
│   └── processed/            # 处理后的数据集
├── src/                      # 源代码
│   ├── __init__.py
│   ├── config.py             # 全局配置（从 .env 加载）
│   ├── models.py             # Pydantic 数据模型
│   ├── database.py           # SQLite 数据库操作
│   ├── llm.py                # Minimax M3 LLM 客户端
│   ├── agents/               # 4 个检测 Agent
│   │   ├── __init__.py
│   │   ├── base.py           # Agent 抽象基类
│   │   ├── semantic.py       # Agent #1: 语义意图分析
│   │   ├── detector.py       # Agent #2: 多维关联检测
│   │   ├── risk.py           # Agent #3: 风险研判
│   │   └── response.py       # Agent #4: 自主响应
│   ├── workflow/             # LangGraph 工作流
│   │   ├── __init__.py
│   │   └── graph.py          # 状态机定义和编排
│   ├── api/                  # FastAPI 后端
│   │   ├── __init__.py
│   │   ├── server.py         # FastAPI 应用实例
│   │   └── routes.py         # REST API 路由
│   └── web/                  # Gradio 前端
│       ├── __init__.py
│       └── ui.py             # Web UI 界面
├── scripts/                  # 工具脚本
│   ├── download_datasets.py  # 数据集下载工具
│   └── run_test.py           # 样例测试脚本
└── tests/                    # 测试目录
    ├── __init__.py
    └── samples/              # 测试样例
```

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/your-username/Phishing_detector.git
cd Phishing_detector
```

### 2. 创建虚拟环境

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Mac/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

### 4. 配置环境变量

复制环境变量模板并填入 API Key：

```bash
copy .env.example .env
```

编辑 `.env` 文件，填入 Minimax API Key：

```env
# 从 https://platform.minimaxi.com 获取
MINIMAX_API_KEY=your-actual-api-key-here
MINIMAX_BASE_URL=https://api.minimaxi.chat/v1
MINIMAX_MODEL=MiniMax-Text-01
```

其他配置项（可选）：
- `DATABASE_URL`: SQLite 数据库路径（默认 `sqlite:///./phishing_detector.db`）
- `API_HOST`: API 服务地址（默认 `0.0.0.0`）
- `API_PORT`: API 服务端口（默认 `8000`）
- `UI_PORT`: UI 服务端口（默认 `7860`）
- `LOG_LEVEL`: 日志级别（默认 `INFO`）

### 5. 运行系统

**全栈模式（推荐）**：同时启动 API + UI
```bash
python main.py
```

启动后访问：
- API: http://localhost:8000
- UI: http://localhost:7860

**其他启动模式：**

```bash
# 仅启动 API 服务
python main.py --api

# 仅启动 UI（需要 API 已运行）
python main.py --ui

# 运行测试样例
python main.py --test

# UI 使用 Gradio share 链接（公网访问）
python main.py --share
```

### 6. 使用系统

1. 打开浏览器访问 http://localhost:7860
2. 在输入框中粘贴邮件内容，或填写结构化字段
3. 点击"开始分析"按钮
4. 实时查看 4 个 Agent 的执行日志
5. 查看完整的分析报告和风险评级

## 数据集获取

项目提供自动化的数据集下载脚本，支持从 HuggingFace 和 GitHub 获取主流钓鱼邮件数据集。

### 下载数据集

```bash
python scripts/download_datasets.py
```

脚本提供交互式菜单：
1. 下载 HuggingFace 数据集
2. 下载 PhishFuzzer 数据集
3. 全部下载（推荐）
4. 仅处理已有数据集

### 数据来源

**1. HuggingFace 数据集**
- `cybersectony/PhishingEmailDetectionv2.0`: 约 20 万封钓鱼邮件，质量较好
- `drorrabin/phishing_emails-data`: 约 3 万封，较轻量

**2. PhishFuzzer 数据集**
- GitHub 仓库: https://github.com/josephdouglass/PhishFuzzer
- 23,100 封 LLM 生成的钓鱼/垃圾/正常邮件
- 包含 URL 和附件元数据

### 数据管理

- 原始数据存放在 `data/raw/` 目录
- 处理后的统一格式数据在 `data/processed/` 目录
- **数据集文件不上传到 GitHub**（已在 `.gitignore` 中排除）
- 脚本会自动将不同来源的数据转换为统一格式：

```json
{
  "text": "邮件全文",
  "label": 0,  // 0=正常, 1=钓鱼
  "source": "数据集来源"
}
```

## API 文档

FastAPI 提供 RESTful 接口，访问 http://localhost:8000/docs 查看交互式文档。

### 核心接口

#### 1. 分析邮件（同步）

```http
POST /api/analyze
Content-Type: application/json

{
  "subject": "邮件主题",
  "sender": "sender@example.com",
  "body": "邮件正文",
  "urls": ["http://example.com"],
  "has_attachment": false
}
```

**响应：**
```json
{
  "email_id": 123,
  "report_id": 456,
  "is_phishing": true,
  "risk_score": 85,
  "risk_level": "high",
  "semantic": { ... },
  "detection": { ... },
  "risk": { ... },
  "response": { ... },
  "workflow_log": [ ... ]
}
```

#### 2. 分析邮件（流式 SSE）

```http
POST /api/analyze/stream
Content-Type: application/json

{
  "subject": "邮件主题",
  "body": "邮件正文"
}
```

**响应：** Server-Sent Events 流，逐步返回每个 Agent 的执行过程

事件类型：
- `agent_start`: Agent 开始执行
- `agent_log`: Agent 执行日志
- `agent_done`: Agent 完成，附带结果
- `complete`: 全部完成，附带最终报告
- `error`: 执行出错

#### 3. 获取历史邮件

```http
GET /api/emails?limit=50
```

#### 4. 获取分析报告

```http
GET /api/reports?limit=50
```

#### 5. 获取统计概览

```http
GET /api/stats
```

**响应：**
```json
{
  "total_emails": 100,
  "total_reports": 100,
  "phishing_detected": 35,
  "safe_emails": 65,
  "avg_risk_score": 42.5
}
```

## 协作开发流程

### 1. Fork 和 Clone

```bash
# 在 GitHub 上 Fork 项目
# 然后 Clone 自己的 Fork
git clone https://github.com/YOUR-USERNAME/Phishing_detector.git
cd Phishing_detector

# 添加上游仓库
git remote add upstream https://github.com/ORIGINAL-OWNER/Phishing_detector.git
```

### 2. 创建功能分支

```bash
# 同步上游最新代码
git fetch upstream
git checkout main
git merge upstream/main

# 创建功能分支（命名规范）
git checkout -b feature/semantic-agent-optimization
git checkout -b fix/url-detection-bug
git checkout -b docs/update-readme
```

**分支命名规范：**
- `feature/xxx`: 新功能
- `fix/xxx`: Bug 修复
- `docs/xxx`: 文档更新
- `refactor/xxx`: 代码重构
- `test/xxx`: 测试相关

### 3. 提交代码

使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```bash
# 格式: <type>(<scope>): <description>
git commit -m "feat(semantic): 增加 BEC 诈骗识别能力"
git commit -m "fix(detector): 修复短链检测误报问题"
git commit -m "docs(readme): 更新 API 文档示例"
git commit -m "refactor(risk): 优化评分融合算法"
git commit -m "test(workflow): 添加边界情况测试用例"
```

**常用 type：**
- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更新
- `style`: 代码格式调整
- `refactor`: 重构
- `test`: 测试
- `chore`: 构建/工具

### 4. 推送和创建 PR

```bash
# 推送到自己的 Fork
git push origin feature/semantic-agent-optimization

# 在 GitHub 上创建 Pull Request
# - 标题遵循 Conventional Commits 格式
# - 描述清楚改动内容和原因
# - 关联相关 Issue（如果有）
```

### 5. Code Review

**PR 审查要点：**
- 代码是否符合项目风格
- 是否有充分的测试
- 是否更新了相关文档
- 是否引入了新的依赖
- 性能影响评估

**审查流程：**
1. 至少 1 人 Approve
2. 通过 CI 检查（如有）
3. 解决所有 Review Comments
4. 使用 Squash Merge 合并

### 6. 分支保护规则（建议）

在 GitHub 仓库设置中配置：
- `main` 分支禁止直接推送
- 要求 PR 合并前必须通过 Review
- 要求合并前必须通过 CI 检查
- 启用 Squash Merge，保持提交历史整洁

## 技术栈

### 核心框架
- **LangGraph**: Agent 工作流编排
- **FastAPI**: 高性能 REST API
- **Gradio**: Web UI 界面
- **Pydantic**: 数据模型和校验

### LLM 和 AI
- **Minimax M3**: 大语言模型（通过 OpenAI 兼容接口调用）
- **LangChain Core**: LLM 调用抽象

### 数据存储
- **SQLite**: 轻量级嵌入式数据库
- **WAL 模式**: 提升并发性能

### 数据处理
- **Pandas**: 数据集处理和分析
- **HuggingFace Datasets**: 数据集下载和加载

### 开发工具
- **Uvicorn**: ASGI 服务器
- **python-dotenv**: 环境变量管理
- **SSE-Starlette**: Server-Sent Events 支持

## 许可证

MIT License

Copyright (c) 2025 PhishingDetector Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## 相关链接

- 技术设计文档: [TECH.md](./TECH.md)
- Minimax API 文档: https://platform.minimaxi.com
- LangGraph 文档: https://langchain-ai.github.io/langgraph/
- FastAPI 文档: https://fastapi.tiangolo.com
- Gradio 文档: https://www.gradio.app
