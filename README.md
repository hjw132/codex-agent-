# 多 Agent 自动协作说明

## 1. 功能概览
本项目通过 `codex exec` 构建一个可配置的多 Agent 协作调度器（`n>=2`），核心流程如下：

1. 启动时定义 Agent 列表、总控 Agent、每个 Agent 职责。
2. 第 1 轮由总控 Agent（`LEAD`）先做任务拆解与协作大纲。
3. 各 Agent 在共享文档 `AGENT_SYNC.md` 中通过结构化字段互相投喂提示词：
   - `[AGENT][Rk][FEED_TO]=...`
   - `[AGENT][Rk][FEED_PROMPT]=...`
   - `[AGENT][Rk][READY_TO_END]=YES|NO`
4. 调度器优先执行被 `FEED_TO` 指向的 Agent。
5. 只有所有 Agent 都写 `READY_TO_END=YES` 才会自动结束，并写入：
   - `[TASK][Rk][DONE]=YES`
   - `[TASK][Rk][CLOSED]=YES`

## 2. 目录与文件
1. 主调度脚本：`scripts/auto_dual_agent.py`
2. 启动包装脚本：`scripts/run_dual_agent.sh`
3. 协作文档：`AGENT_SYNC.md`
4. 每轮输出目录：`.agent_runs/`

## 3. 快速开始
```bash
# 进入你克隆下来的仓库根目录
cd <你的仓库根目录>
chmod +x scripts/run_dual_agent.sh scripts/auto_dual_agent.py
```

最小启动示例：
```bash
AGENTS=LEAD,DEV,QA \
LEAD_AGENT=LEAD \
scripts/run_dual_agent.sh "实现某个功能并完成测试闭环" \
  --max-turns 30 \
  --agent-role LEAD=总控规划与收敛 \
  --agent-role DEV=实现与自测 \
  --agent-role QA=测试回归与验收
```

## 4. 常用启动模板
前后端 + 测试四角色：
```bash
AGENTS=LEAD,BACKEND,FRONTEND,QA \
LEAD_AGENT=LEAD \
scripts/run_dual_agent.sh "搭建一个博客网页，包含前后端" \
  --max-turns 40 \
  --agent-role LEAD=总控规划与收敛 \
  --agent-role BACKEND=后端API与数据层 \
  --agent-role FRONTEND=前端页面与交互 \
  --agent-role QA=测试与缺陷回归
```

启用无沙盒（高风险）：
```bash
scripts/run_dual_agent.sh "任务描述" --dangerous
```

## 5. 每个 Agent 权限策略
支持按 Agent 单独配置权限：
1. `read-only`：只读，不允许写文件。
2. `workspace-write`：可写当前工作区。
3. `danger-full-access`：沙盒模式下的高权限访问。
4. `bypass`：无沙盒，按当前系统用户权限执行。

注意：
1. `bypass` 不是自动 root/sudo。
2. 是否能 `sudo` 取决于当前系统用户本身权限。

通过命令行逐个设置：
```bash
scripts/run_dual_agent.sh "任务描述" \
  --agent-permission LEAD=read-only \
  --agent-permission BACKEND=workspace-write \
  --agent-permission QA=read-only
```

通过环境变量一次设置：
```bash
AGENT_PERMISSIONS=LEAD=read-only,BACKEND=workspace-write,QA=read-only \
scripts/run_dual_agent.sh "任务描述"
```

## 6. 角色职责配置方式
方式 A：命令行
```bash
scripts/run_dual_agent.sh "任务描述" \
  --agent-role LEAD=总控规划与收敛 \
  --agent-role DEV=编码与重构 \
  --agent-role QA=测试与回归
```

方式 B：JSON 文件（推荐大规模角色）
`roles.json` 示例：
```json
{
  "LEAD": "总控规划与收敛",
  "BACKEND": "后端API与数据层",
  "FRONTEND": "前端页面与交互",
  "QA": "测试与缺陷回归"
}
```

使用方式：
```bash
scripts/run_dual_agent.sh "任务描述" --agent-roles-file roles.json
```

## 7. 模型与思考强度（可选）
你可以在启动时指定模型与推理强度：

1. 模型参数：`--model` 或环境变量 `MODEL_NAME`
2. 思考强度：`--reasoning-effort` 或环境变量 `REASONING_EFFORT`
3. 思考强度可选值：`low`、`medium`、`high`、`xhigh`

命令行方式：
```bash
scripts/run_dual_agent.sh "任务描述" \
  --model gpt-5.3-codex \
  --reasoning-effort high
```

环境变量方式：
```bash
MODEL_NAME=gpt-5.3-codex \
REASONING_EFFORT=high \
scripts/run_dual_agent.sh "任务描述"
```

说明：
1. 不指定时使用本机 Codex CLI 默认配置（例如 `~/.codex/config.toml`）。
2. 强度越高通常推理更充分，但耗时和 token 也可能更高。

## 8. 共享文档协议（必须遵守）
每个 Agent 一轮必须至少追加一块：
```text
[AGENT_X][Rk][<ISO8601 timestamp>]
- Role:
- Summary:
- Files:
- Commands:
- Results:
- Next:
[AGENT_X][Rk][FEED_TO]=AGENT_Y,AGENT_Z or NONE
[AGENT_X][Rk][FEED_PROMPT]=single-line prompt or NONE
[AGENT_X][Rk][READY_TO_END]=YES|NO
```

规则：
1. `FEED_TO` 只能指向已注册的其他 Agent，不能指向自己。
2. `FEED_PROMPT` 建议写成可执行的下一步动作。
3. 未完成时必须保持 `READY_TO_END=NO`。

## 9. 运行中如何观察进度
查看实时轮次日志：
```bash
tail -f AGENT_SYNC.md
```

查看每轮 Agent 最后一条输出：
```bash
ls -lt .agent_runs
tail -f .agent_runs/R1_T1_LEAD.last_message.txt
```

## 10. 后台运行与停止
后台运行：
```bash
AGENTS=LEAD,DEV,QA LEAD_AGENT=LEAD \
scripts/run_dual_agent.sh "任务描述" --max-turns 50 > run.log 2>&1 &
echo $! > .agent_runs/runner.pid
```

查看后台日志：
```bash
tail -f run.log
```

停止后台任务：
```bash
kill "$(cat .agent_runs/runner.pid)"
```

## 11. 结束条件与自动停止
满足以下条件才会自动“圆满结束”：
1. 当前 round 内所有 Agent 均写 `READY_TO_END=YES`。
2. 调度器自动写入 `DONE` 与 `CLOSED` 标记。

如果超过 `--max-turns`：
1. 调度器不会无限运行。
2. 会写入 `[TASK][Rk][AUTO_STOP]=MAX_TURNS` 作为停止原因。

## 12. 常见问题
`codex command not found`：
1. 脚本会自动尝试从 VSCode 扩展目录找 `codex`。
2. 也可以手动指定：`--codex-bin /path/to/codex`

为什么 VSCode 聊天栏看不到多个会话：
1. 该方案走的是 CLI，会话日志在文档和 `.agent_runs`。
2. 不会自动在 VSCode Chat UI 新建多个可视化对话标签。
