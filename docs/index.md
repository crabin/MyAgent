# MyAgent 文档

本目录记录这个 fork 的使用说明、代码结构和专属化改造方案。上游 Pi 的完整功能文档仍在 `packages/coding-agent/docs/`，这里放面向本项目的维护说明。

## 文档入口

- [使用说明](usage.md) - 从源码运行、认证、会话和配置目录。
- [代码说明](code-guide.md) - monorepo 包结构、核心入口和默认提示词位置。
- [专属化说明](personalization.md) - 当前已经改动的专属化点，以及后续建议。

## 当前定位

MyAgent 是基于 Pi coding agent 的个人专属命令行 agent。当前改造保持底层包名和 workspace 依赖不变，优先调整运行名称、配置目录、默认身份和项目文档，避免引入 lockfile 和发布链路的大范围变化。

## 关键路径

- CLI 包：`packages/coding-agent`
- 默认系统提示词：`packages/coding-agent/src/core/system-prompt.ts`
- CLI 名称与配置目录：`packages/coding-agent/package.json` 的 `piConfig`
- 全局用户配置目录：`~/.myagent/agent`
- 项目本地配置目录：`.myagent/`

