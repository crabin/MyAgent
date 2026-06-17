# 使用说明

## 从源码运行

在仓库根目录安装依赖：

```bash
npm install --ignore-scripts
```

从源码启动：

```bash
./pi-test.sh
```

`pi-test.sh` 仍然是开发脚本名称，它会直接运行 `packages/coding-agent/src/cli.ts`。正式构建后的命令名已经改为 `myagent`。

## 构建后的命令

构建 CLI 包：

```bash
npm --prefix packages/coding-agent run build
```

构建后 npm bin 名称是：

```bash
myagent
```

Bun 单文件二进制输出位置改为：

```bash
packages/coding-agent/dist/myagent
```

## 配置目录

MyAgent 使用独立配置目录，不复用上游 `~/.pi/agent`：

```text
~/.myagent/agent
```

项目本地资源目录也改为：

```text
.myagent/
```

常用文件：

- `~/.myagent/agent/settings.json` - 全局设置。
- `~/.myagent/agent/models.json` - 自定义模型。
- `~/.myagent/agent/sessions/` - 会话存储。
- `.myagent/settings.json` - 当前项目设置。
- `.myagent/SYSTEM.md` - 当前项目的系统提示词覆盖。
- `.myagent/APPEND_SYSTEM.md` - 当前项目追加到系统提示词的内容。

## 认证

可以使用订阅登录：

```bash
myagent
/login
```

也可以通过环境变量提供 API key，例如：

```bash
export ANTHROPIC_API_KEY=sk-ant-...
myagent
```

## 检查

代码变更后运行：

```bash
npm run check
```

如果只改文档，不需要运行检查。

