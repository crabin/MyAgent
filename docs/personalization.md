# 专属化说明

## 已完成

- CLI 应用名改为 `myagent`。
- 构建后的 npm bin 改为 `myagent`。
- Bun 二进制输出改为 `dist/myagent`。
- 全局配置目录改为 `~/.myagent/agent`。
- 项目本地资源目录改为 `.myagent/`。
- 运行标记环境变量从固定 `PI_CODING_AGENT` 改为按应用名生成的 `MYAGENT_CODING_AGENT`。
- 默认系统提示词改为 MyAgent 身份。
- 新增根目录 `docs/`，集中放本 fork 的使用说明和代码说明。

## 暂不改动

- npm 包名仍是 `@earendil-works/pi-coding-agent`。
- workspace 内部包名仍是 `@earendil-works/pi-*`。
- 上游功能文档仍保留在 `packages/coding-agent/docs/`。
- `pi-test.sh` 仍保留原名，作为源码开发脚本。

这些内容牵涉 package lock、shrinkwrap、发布脚本、文档链接和测试期望。当前阶段保持不动，降低改造风险。

## 推荐的个人配置方式

把经常变化的个人偏好放到配置目录，而不是写死在源码里：

```text
~/.myagent/agent/
  settings.json
  SYSTEM.md
  APPEND_SYSTEM.md
  skills/
  prompts/
  themes/
```

项目级规则放到当前仓库：

```text
.myagent/
  settings.json
  SYSTEM.md
  APPEND_SYSTEM.md
  skills/
  prompts/
  themes/
```

适合放进 `SYSTEM.md` 的内容：

- 回答语言和风格。
- 默认工作流程。
- 常用命令限制。
- 代码审查偏好。
- 个人项目路径和命名约定。

适合做成 skill 或 prompt template 的内容：

- 重复执行的工作流。
- 固定格式的审查、总结、发布说明。
- 特定技术栈的步骤说明。

## 后续改造路线

1. 决定是否彻底改 npm package scope 和仓库 README 品牌。
2. 把个人默认规则迁移到 `~/.myagent/agent/SYSTEM.md`。
3. 为常用任务新增 `skills/` 和 `prompts/`。
4. 只在确认要发布自己的包时，再改 `package-lock.json`、`npm-shrinkwrap.json`、release 脚本和安装文档。

