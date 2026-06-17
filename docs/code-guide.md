# 代码说明

## 项目结构

这是一个 TypeScript monorepo：

```text
packages/
  ai/            LLM provider 抽象和模型注册。
  agent/         agent loop、消息、工具调用和 harness。
  tui/           终端 UI 组件。
  coding-agent/  最终 CLI、交互模式、配置、扩展、会话和内置工具。
```

## CLI 启动链路

入口顺序：

```text
packages/coding-agent/src/cli.ts
packages/coding-agent/src/main.ts
packages/coding-agent/src/core/agent-session-runtime.ts
packages/coding-agent/src/core/agent-session.ts
```

`cli.ts` 设置进程标题和运行环境标记，然后调用 `main()`。`main.ts` 解析参数、加载设置、选择模型、处理 session，再进入 interactive、print、json 或 rpc 模式。

## 专属名称与配置目录

`packages/coding-agent/src/config.ts` 从 `packages/coding-agent/package.json` 读取：

```json
{
  "piConfig": {
    "name": "myagent",
    "configDir": ".myagent"
  }
}
```

这些值会影响：

- CLI 展示名：`myagent`
- 终端标题：`myagent`
- 全局配置目录：`~/.myagent/agent`
- 项目配置目录：`.myagent`
- 环境变量前缀：`MYAGENT_CODING_AGENT_DIR`、`MYAGENT_CODING_AGENT_SESSION_DIR`

## 默认系统提示词

默认系统提示词在：

```text
packages/coding-agent/src/core/system-prompt.ts
```

当前默认身份已经改成 MyAgent。更强的个人规则建议放在全局或项目提示文件里，而不是继续硬编码：

- 全局：`~/.myagent/agent/SYSTEM.md` 或 settings 里的 prompt 配置。
- 项目：`.myagent/SYSTEM.md` 或 `.myagent/APPEND_SYSTEM.md`。

这样可以避免每次调整个人偏好都改源码。

## 文档来源

- 本 fork 文档：`docs/`
- 上游 CLI 用户文档：`packages/coding-agent/docs/`
- 上游开发说明：`packages/coding-agent/docs/development.md`
- 项目规则：`AGENTS.md`
