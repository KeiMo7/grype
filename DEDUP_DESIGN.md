# 确定性去重设计（deterministic match dedup）

> 实现状态：已落地。新增 `grype/match/dedup` 包（19 个测试用例全绿）、CLI 配置 `dedup`、
> JSON `merge` 审计段、`test/dedup/` 验收工具。默认 `mode: legacy`，现有 golden 零改动。
> 端到端验证（真实 DB）：同一 SBOM 的双路径变体 legacy 8 条 → finding 4 条，diff 契约
> 通过且零误删；amd64/arm64 变体各 4 条独立报告、修复版本不串。

## 问题

同一个镜像扫两次，漏洞数可能不同。根因不在匹配、不在数据库，而在去重键：

- 现有去重键是 `Fingerprint{vulnID, namespace, pkg.ID}`，而 `pkg.ID` 是 syft 对
  `Name/Version/Type/Locations/Licenses/Metadata` 的内容哈希（`syft/pkg/package.go: SetID`，
  CPEs/PURL/FoundBy/Language 被 `hash:"ignore"`）。
- Locations 参与哈希（`file.Location` 只按 Coordinates：RealPath + layerID 取哈希，
  AccessPath 不参与）。同一包经软链接、多层拷贝被发现时，路径集合不同 → `pkg.ID` 不同 →
  同一 finding 产生两条 Match，是否合并取决于包目录构建时的合并顺序，两次扫描可能不一致。
- 不同架构变体上，同一组件被 syft 识别成不同 `Type`（或 metadata 中 Arch 不同）→
  `pkg.ID` 不同 → 去重行为随架构漂移。

目标：把去重规则固定为确定性的、可配置的、可审计的，且默认行为不变。

## 现状（改动前的关键事实）

- 去重只发生在 `match.Matches.Add`（`grype/match/matches.go:70`），按 `Fingerprint` 折叠，
  同键记录通过 `Match.Merge`（`grype/match/match.go:49`）合并：最强记录描述 finding，
  其余字段做并集（fix versions、constraints、advisories、CPEs、Details）。
- 匹配主流程 `VulnerabilityMatcher.searchDBForMatches` 末尾 `match.NewMatches(filtered...)`
  （`grype/vulnerability_matcher.go:282`）是唯一的结果集收敛点；之后还有 ignore/VEX 处理。
- 跨包类型的 finding 天然不合并：fingerprint 含 `pkg.ID`（含 Type）。
  同一 CVE 命中系统包与语言包时，namespace 通常也不同（如 `redhat:distro:*` vs `nvd:cpe`），
  现有测试 `TestMatches_Add_KeepsSeparateSources` 已锁定此行为。
- JSON 输出模型 `models.Match`（`grype/presenter/models/match.go:15`）没有任何合并审计字段；
  内部 `Fingerprint` 不序列化。
- 数据库更新后的状态变化已有 `grype db diff`（`grype/db/v6/diff`），按
  added/removed/modified 分类包级与 CPE 级命中变化。
- 配置入口：`options.Grype`（`cmd/grype/cli/options/grype.go`），经 clio/fangs 从
  YAML/flags/env 加载；库层只接收普通 struct（`matcher.Config` 等）。

## 设计原则与约束

1. **匹配判定一行不改**。新逻辑是匹配完成后的独立收敛阶段，只消费 `[]match.Match`，
   不接触 matcher/search/qualifier。
2. **默认零变化**。不配置时走现有 fingerprint 路径，现有 golden/snapshot 全部保持。
3. **不新增依赖**。只用标准库和现有依赖（hashstructure 已在 match 包使用）。
4. **去重键计算失败 → 保留原始条目**，并在审计报告中计数，绝不丢弃。
5. **可配置合并粒度**，不同场景可切换键的组成。
6. 所有合并决策可解释：合了哪几条、依据是什么、保留哪一条。

## 架构：两层去重

### 第一层（不变）：record 折叠

现有 `Matches.Add` + `Match.Merge` 原封不动。它解决的是「同一 finding 的多条数据库记录」
（同一 CVE 的多个 CPE、直接/间接 advisory），输出仍是按 syft `pkg.ID` 区分的 Match 集合。

### 第二层（新增）：finding 级收敛

新包 `grype/match/dedup`（纯函数，无 I/O），入口：

```go
func Dedup(matches match.Matches, cfg Config) (match.Matches, Report)
```

在 `VulnerabilityMatcher.FindMatchesContext` 中、VEX 处理之后调用（VEX 可能移除条目，
收敛放最后可以保证审计报告与最终输出一致；位置见 `vulnerability_matcher.go:126` 之后）。

`Config{}` 零值 = `ModeLegacy`，此时直接原样返回输入、`Report` 为空 —— 默认行为不变。

### 去重键（可配置）

```go
type Mode string
const (
    ModeLegacy  Mode = "legacy"  // 默认：仅现有 fingerprint 去重
    ModeFinding Mode = "finding" // 确定性 finding 级去重
)

type Config struct {
    Mode             Mode   // legacy | finding
    MaxPaths         int    // 单条 Match 保留的路径上限，0=内部默认(50)，<0=不限
    IncludePackageType bool // 键中是否包含包类型，默认 true
}
```

`ModeFinding` 下每个 Match 计算一个**显式内容键**（不再依赖 syft 的 `pkg.ID`）：

```
FindingKey = hash(
    vuln.ID,
    vuln.Namespace,                    // 来源不同 → 不合并（修复路径/版本方案不同）
    pkg.Name,
    pkg.Version,                       // 版本不同 → 不合并
    pkg.Type,        // IncludePackageType=true 时；系统包 vs 语言包因此分开
    architectureKey, // 见下；跨架构不合并
)
```

注意：键中**不含 location**。同包多路径（软链接、多层拷贝）因此落到同一组并合并，
路径在合并后做并集 —— 这正是需求中的「同一包不同路径 → 一条，列出所有路径」。

#### 架构键（跨架构不合并）

复用 `grype/pkg/qualifier/architecture` 的既有约定（不新造方言表）：

1. 包架构读取对齐该包的 `packageArch`（RpmMetadata.Arch / ApkMetadata.Arch），
   并补充 GolangBin/GolangSource metadata 的 `Architecture`；
2. 经 `canonicalArch` + `DefaultAliases` 归一（`x86_64`→`amd64`、`aarch64`→`arm64`…），
   保证同一 CPU 架构的不同方言拼写落到同一 token；
3. 包 metadata 无架构时回退扫描源架构（`pkg.Context.Source.Metadata` 中的
   `source.ImageMetadata.Architecture`，同样归一）；SBOM/目录源为空则用哨兵
   `"unknown-arch"`；
4. `noarch`/`all`（架构无关包）与 `src` 保留各自稳定 token：它们本就架构中立，
   合并语义与 `architectureQualifier` 的「inert」处理一致。

两次独立扫描 amd64/arm64 变体时，架构键稳定不同 → 绝不跨架构合并。

### 组内合并规则

同一 `FindingKey` 下的 N 条 Match：

1. **选主记录**：复用 `match.compareRecordAuthority` 的排序（detail rank 最强在前，
   再比 PackageName/Status/Unaffected）。`Unaffected=true` 的记录天然排最后，
   不会让「不受影响」记录盖过「受影响」记录。
2. **字段合并**：主记录为 base，对组内其余记录逐个调用现有 `Match.Merge` 的同构逻辑。
   `Merge` 目前要求 fingerprint 相等，因此在 dedup 包内抽出等价的
   `mergeFields(base, other *Match)`（把 `match.go` 中 union 逻辑提取为包内可复用函数，
   `Merge` 改为调用它，行为不变）。
3. **路径并集**：`base.Package.Locations.Add(other.Package.Locations.ToSlice()...)`，
   排序后截断到 `MaxPaths`；截断时设置审计标记并记录被截断数量。
4. **被合并版本留痕**：每条被合并记录的 `(pkg.Version, vuln.Constraint, fix.Versions,
   状态)` 记入审计结构，同时主记录的 fix versions 仍由 union 逻辑保留（不丢修复版本）。
5. **架构保护**：合并前断言 `architectureKey` 相等，不等则拒绝合并（理论上不会发生，
   属于防御性检查，触发时计入 Report 的 failures 并保留原条目）。

### 失败降级

- `hashstructure.Hash` 返回 error（或键字段提取 panic 被 recover）→ 该条 Match 不参与分组，
  原样进入输出，`Report.Failures++` 并记录原因与匹配标识。
- 路径数超上限 → 保留前 N 条（按 location 的 RealPath 排序后截断，保证确定性），
  `MergedEntry.PathsTruncated=true`、`PathsDropped=n`。

## 审计输出（多路径命中时能看出为什么合并）

### 内部结构

`dedup.Report` 随 `VulnerabilityMatcher` 返回（新增第三个返回值的访问方式：在 matcher 上
保留字段 `LastDedupReport *dedup.Report`，避免改动 `FindMatches` 已公开的签名；
`deprecated.go` 的旧 API 不受影响）。

```go
type Report struct {
    Mode             string
    InputCount       int
    OutputCount      int
    MergedGroups     []MergedGroup
    Failures         []KeyFailure
    PathsTruncated   int
}

type MergedGroup struct {
    Key          string        // FindingKey 的十六进制
    Reason       string        // "same-vuln-package-multiple-locations" 等
    Kept         MatchRef      // 保留的主记录
    Merged       []MergedEntry // 被合并条目明细
}

type MergedEntry struct {
    Fingerprint      string
    PackageVersion   string
    Constraint       string
    FixVersions      []string
    Paths            []string   // 该条目贡献的路径（RealPath；AccessPath 不同时附 accessPath）
    Status           string
    Unaffected       bool
    PathsTruncated   bool
    PathsDropped     int
}

type MatchRef struct {
    VulnID      string
    Namespace   string
    PackageName string
    Version     string
    Type        string
    Arch        string
    Fingerprint string
}
```

### JSON 输出

`models.Match` 增加可选字段（`omitempty`，legacy 模式与无合并时不出现，现有 golden 不变）：

```json
"merge": {
  "mergedFrom": [
    {"fingerprint": "...", "packageVersion": "1.2.3", "constraint": "< 2.0",
     "fixVersions": ["2.0"], "paths": ["/a/lib.jar", "/b/lib.jar"],
     "status": "active", "unaffected": false}
  ],
  "pathsTruncated": false,
  "pathsDropped": 0,
  "reason": "same-vuln-package-multiple-locations"
}
```

完整的 `Report`（含 failures、计数）另通过一个显式开关输出：配置
`dedup.audit-report: <path>` 时写 JSON 文件；不开启则不产生额外文件。
标注员据此可以逐条判断：哪几条合了、依据、保留的是哪条。

## 状态变化追踪（DB 更新后 unaffected → affected）

不新建机制，复用现有 `grype db diff <old.db> <new.db>`，且其测试已覆盖该场景：

- differ 的包表把 affected/unaffected handle 用 UNION ALL 合并并显式带 status 列
  （`grype/db/v6/diff/package_tables.go:127,152`，unaffected 恒为 not-vulnerable 状态）。
- `Test_packageStatusStates` 已钉死全部 15 种状态组合，其中明确包含：
  「旧库 not-vulnerable → 新库 vulnerable」报 **added**、反向报 **removed**；
  `Test_packageModifiedRecordSets` 补充 modified 语义。
- 因此本项目不新增 diff 测试夹具（flat-file 建库成本高且无新增覆盖），
  改为在验收文档中引用上述测试作为状态追踪的回归基线，并在 dedup 包测试中保证
  第一层 record 折叠不会吞掉 Unaffected 记录的 Details。
- 在用户文档中写明：跨数据库快照的状态追踪用 `grype db diff`，扫描 JSON 只反映当前库状态。

## 配置接线

YAML（`.grype.yaml`）：

```yaml
dedup:
  mode: legacy            # legacy（默认）| finding
  max-paths: 50
  include-package-type: true
  audit-report: ""        # 可选：审计报告 JSON 输出路径
```

- 库层：`grype/match/dedup/config.go` 定义 `Config` + `Validate()`（模式枚举、
  maxPaths 范围），`VulnerabilityMatcher` 增加 `DedupConfig dedup.Config` 字段。
- CLI 层：`cmd/grype/cli/options/` 新增 `dedup.go`（`dedupConfig`，含
  `PostLoad` 校验与 `DescribeFields`），挂到 `options.Grype.Dedup`；
  `root.go:227` 构造 matcher 时传入。
- 不新增 CLI flag（YAML/env 即可，env 前缀 `GRYPE_DEDUP_*` 由 fangs 自动支持），
  避免扩大公开 CLI 面。

## 三条合并语义的落实对照

| 需求 | 规则落点 |
|---|---|
| 同 CVE 同包不同版本记录 → 留最严重一条，记录被合并版本 | 第一层 record 折叠 + 第二层组内选主（`compareRecordAuthority`，Unaffected 垫底）；版本明细进 `MergedEntry` |
| 同 CVE 不同包（系统包/语言包）→ 分开报 | 键含 `pkg.Type`（可关）+ namespace 不同天然不同键；现有 `KeepsSeparateSources` 测试继续锁定 |
| 同包不同路径（软链接/多层拷贝）→ 一条 + 全部路径 | 键不含 location；`Locations` 并集，超上限截断标注 |
| 跨架构不合并 | architectureKey 入键，amd64/arm64 各自成组 |

## 验收方案

### A. 固定基线 diff（核心验收物）

`test/dedup/` 下新增确定性夹具与测试，不依赖网络/真实镜像/真实 DB 下载：

1. **夹具构造**：手工构造 `pkg.Package` + `match.Match` 集合，覆盖
   - 多路径同包（两个 location，含 RealPath/AccessPath 不同的虚拟 location 模拟软链接）；
   - 同 CVE 跨包类型（rpm + python 各一条）；
   - 同 CVE 同包多条版本记录（含一条 Unaffected）；
   - 模拟双架构：同 name/version，metadata Arch 分别 amd64/arm64；
   - 键计算失败注入（hashstructure 不可失败的前提下，用不可哈希字段构造触发 recover 路径）。
2. **golden 基线**：`TestDedup_GoldenBaseline` 对 legacy 与 finding 两种模式分别输出
   逐条 JSON（含 merge 审计段），golden 文件入库。
3. **只允许路径列表差异**：`TestDedup_LegacyVsFindingDiff` 对两套输出做逐条 diff，
   断言除 `merge.mergedFrom[].paths` / artifact.locations 及合并计数外，无任何条目增减、
   无字段值变化；任何额外差异直接测试失败。
4. **无漏洞误删断言**：finding 模式输出的每条 Match 都能在输入集合中按
   `(vuln.ID, namespace, pkg.Name, pkg.Version)` 找到来源；输入的每个该四元组都仍存在于输出。
5. **合并明细断言**：每个 MergedGroup 校验 Kept 是组内 authority 最强者、
   Merged 列表与输入一一对应、Reason 非空。

### B. 跨架构专项用例

`TestDedup_CrossArchitectureNeverMerges`：同一输入包集跑两遍，分别注入
`source.ImageMetadata{Architecture: "amd64"}` 与 `"arm64"`：

- 两次输出条目数相等且等于输入条目数（不发生跨架构合并）；
- 各自的 fix versions 不串（amd64 条目只含 amd64 记录的修复版本，arm64 同理）；
- 再验证把两个变体的 Match 混进一个 Matches 集合时，仍按架构键分成两组。

### C. 端到端镜像/SBOM 验收脚本

`test/dedup/acceptance.sh`（文档化，可手动运行）：

1. 固定 DB 快照（目录路径参数化，脚本内 `GRYPE_DB_VALIDATE_AGE=false` 等）；
2. 对 `test/cli/testdata` 中现有 SBOM 夹具分别用改动前二进制（`git stash` 构建 baseline）
   与改动后二进制各扫一遍，输出 JSON；
3. 调用 `test/dedup/diff_reports.py`（独立目录、`python3 -I` 运行）：
   - 输出总条目数、合并条目数、合并明细（哪几条、依据、保留条）；
   - legacy 模式要求两份 JSON 完全一致；
   - finding 模式允许的差异白名单仅为 merge 段与 locations，其余全部报错退出。
4. 多架构验收用 SBOM 夹具：同一镜像的 amd64/arm64 SBOM 各扫一遍，断言两份报告、
   条目数为两份、修复版本不串。

### D. 回归

- `go test ./...` 全量通过；legacy 为默认，所有现有 golden/snapshot 零改动
  （新 JSON 字段 omitempty）。
- `grype/match` 包既有测试（`TestMatches_Add_*`、`TestMatch_Merge_*`）原样通过，
  证明第一层未受影响。

## 改动文件清单（实际）

新增：
- `grype/match/dedup/`：`config.go`（模式/上限/校验）、`key.go`（显式内容键 +
  架构归一）、`dedup.go`（分组、合并、截断、降级）、`report.go`（审计结构）、
  `dedup_test.go`（16 个用例，含跨架构、降级、无丢失断言）
- `cmd/grype/cli/options/dedup.go` + `dedup_test.go`
- `cmd/grype/cli/commands/dedup_audit.go`（审计文件输出）
- `test/dedup/diff_reports.py`（逐条 diff，差异白名单仅 merge/locations）、
  `multiarch_check.py`、`acceptance.sh`

修改：
- `grype/match/match.go`：抽出 `mergeFields`（纯重构）、导出 `CompareRecordAuthority`/
  `MergeFields`、新增 `MergeAudit`/`MergedRecord`
- `grype/pkg/qualifier/architecture/qualifier.go`：导出 `Canonicalize`（薄封装，复用别名表）
- `grype/vulnerability_matcher.go`：挂载 `DedupConfig`、VEX 后调用第二层、保留 `LastDedupReport`
- `cmd/grype/cli/options/grype.go`：嵌入 `Dedup dedupConfig`
- `cmd/grype/cli/commands/root.go`：传配置、按需写审计文件
- `grype/presenter/models/match.go`：新增 omitempty 的 `Merge` 段 + 测试
