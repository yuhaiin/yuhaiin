# 用户管理与代理协议认证设计

## 1. 文档目的

本文档描述在现有 yuhaiin 配置模型上增加“用户管理”的设计方案，目标是：

1. inbound 不再直接保存 HTTP、SOCKS5、Yuubinsya、Mixed、SOCKS4A 或 AEAD transport 的认证材料；AuthCenter 根据所有兼容用户自动建立认证索引。
2. outbound 不再在节点协议中手工填写密码、UUID、用户名/密码、AuthKey 等认证材料，而是引用用户管理中的用户。
3. 覆盖当前代码中所有真正携带代理认证或敏感密钥的协议，同时明确哪些字段只是网络拓扑、TLS、伪装或设备密钥，不应误认为代理用户。
4. 兼容现有 inbounds_v2、nodes_v2、旧版 SQLite 配置、节点订阅和 Android/AAR 使用方式，做到可迁移、可回滚、可验证。

本文档是实现前的详细设计，不包含具体代码修改。

## 2. 当前代码现状

### 2.1 inbound 认证链路

当前流程是：

~~~text
InboundStore/HTTP API
        |
        v
contract.Inbound.Protocol
        |
        v
pkg/inbound/contract_listener.go: contractProtocol
        |
        +--> http.ServerConfig{Username, Password}
        +--> socks5.ServerConfig{Username, Password}
        +--> yuubinsya.ServerConfig{Password}
        +--> mixed.ServerConfig{Username, Password}
        +--> socks4a.ServerConfig{Username}
~~~

contractProtocol 当前直接读取 pkg/contract/inbound/types.go 中的协议字段，再把明文认证材料交给 server。HTTP 和 SOCKS5 使用单个用户名/密码；SOCKS4A 使用用户名；当前 Yuubinsya 实现使用密码派生认证 hash。yuubinsya2 已经定义了 UserAuth.Verify(user, password) 接口，但当前 inbound 注册路径仍使用旧的密码 hash 协议，因此设计必须兼容两种语义。

当前 inbound 可配置协议分为：

| 协议 | 当前认证材料 | 是否需要用户管理 | 设计 |
| --- | --- | --- | --- |
| HTTP | username + password，Basic/Proxy-Authorization | 是 | 引用一个或多个用户名/密码用户 |
| SOCKS5 | username + password，RFC 1929 | 是 | 引用一个或多个用户名/密码用户 |
| Yuubinsya | password，派生协议 hash | 是 | 引用密码用户；未来切换 Yuubinsya2 时复用用户名/密码用户 |
| Mixed | 内部同时启动 HTTP、SOCKS5、SOCKS4A | 是 | 共享同一组用户引用 |
| SOCKS4A | username | 是 | 引用用户名用户，或允许用户名/密码用户忽略密码 |
| TProxy | 无协议层用户认证 | 否 | 不增加用户引用 |
| Redir | 无协议层用户认证 | 否 | 不增加用户引用 |
| Tun | 无协议层用户认证 | 否 | 不增加用户引用 |
| Reverse HTTP | 当前为反向连接 URL/TLS | 否 | URL/TLS 保持原配置；如未来增加 HTTP Basic，再单独增加认证引用 |
| Reverse TCP | 无用户认证 | 否 | 保持原配置 |
| None | 无用户认证 | 否 | 保持原配置 |

此外，inbound transport 中的 AEADTransport.Password 是传输层共享密钥，不是 HTTP/SOCKS 用户。它也不再写在 transport contract 中：AuthCenter 为 AEAD server 建立由所有 inbound/both Basic 用户 password 组成的密钥索引，协议适配器只调用 AuthCenter 提供的 AEAD authenticator，不接触用户表或自行比较密码。由于当前 AEAD wire 层原本只支持一个共享密码，落地时需要把 server handshaker 扩展为支持多 key 尝试；这不是新增 UserID，而是中心认证机构内部的索引实现。

### 2.2 outbound 认证链路

项目没有单独的 pkg/outbound；outbound 是 pkg/contract/node.Node 的 Chain。pkg/register.ContractDialer 按 chain 顺序调用 ContractWrap，每个协议通过 RegisterContractPoint 注册自己的客户端构造函数。当前节点 contract JSON 直接放在 nodes_v2.data_json 中。

当前 outbound 协议中涉及认证或敏感密钥的字段如下：

| 协议 | 当前字段 | 认证/密钥语义 | 设计 |
| --- | --- | --- | --- |
| Shadowsocks | password | 加密密码 | 引用密码用户 |
| ShadowsocksR | password | 加密密码 | 引用密码用户 |
| VMess | id/UUID | 用户 UUID，alterID 是协议参数 | 引用 UUID 用户，alterID 保留在协议配置 |
| VLESS | uuid | 用户 UUID | 引用 UUID 用户 |
| Trojan | password | 服务端认证密码 | 引用密码用户 |
| SOCKS5 | user + password | 上游 SOCKS5 用户 | 引用用户名/密码用户 |
| HTTP | user + password | 上游 HTTP Proxy Basic 用户 | 引用用户名/密码用户 |
| Yuubinsya | password | 协议共享密码 | 引用密码用户 |
| AEAD | password | AEAD 传输共享密钥 | 引用 Basic 用户，只读取 password |
| Tailscale | auth_key | Tailscale AuthKey | 引用 token 用户 |
| WireGuard | secretKey | 本地 WireGuard private key | 保持在 WireGuard 配置中，暂不纳入用户管理 |
| WireGuard peer | preSharedKey | peer 级别预共享密钥 | 保持在 WireGuard peer 配置中，暂不纳入用户管理 |
| Cloudflare WARP MASQUE | private_key | 本地隧道 private key | 保持在 WARP 配置中，暂不纳入用户管理 |

以下协议当前没有代理用户认证，不增加用户引用：WebSocket、QUIC、Obfs HTTP、Simple/Fixed、None、Direct、Reject、HTTP2、Reality outbound、TLS、Mux、Drop、Bootstrap DNS Warp、Set、TLS termination、HTTP termination、HTTP Mock、Network Split、Proxy、FixedV2、PointAsEndpoint。

其中 TLS certificate private key、Reality inbound private key、WireGuard private key 等属于设备/隧道密钥，不是“可登录代理的用户”。本期只抽离代理认证和 AEAD password；这些设备/隧道密钥继续保留在各自配置中，后续如需统一管理应单独设计 secret/vault。

### 2.3 当前存储与 API 特点

- inbound 通过 InboundStore 保存到 SQLite inbounds_v2，完整 contract 序列化到 data_json。
- node 通过 NodeStore 保存到 nodes_v2，完整 contract 序列化到 data_json。
- SQLite 使用版本迁移数组，目前 schema version 为 5。
- v2 API 采用 route table + POST JSON RPC，前端 contract 可以通过现有生成器生成。
- 当前的 JSON contract 是“完整对象保存”模式，因此用户引用的合法性需要在 store 层和 runtime 构建前同时校验，不能只依赖前端。

## 3. 目标与非目标

### 3.1 目标

- 用户集中管理、集中修改、集中禁用。
- 所有启用且 Usage=inbound 或 both 的兼容用户自动对相应 inbound 生效；inbound 不再保存 UserIDs，也不提供入站用户选择器。
- 一个用户可以被多个 inbound 或 outbound 节点复用。
- 节点协议只保存 userId，不保存认证明文。
- 用户被删除、禁用或认证材料变更后，不产生静默失效或悬空引用。
- 远程订阅节点也能完成认证字段迁移，并且不会在每次订阅刷新时无限生成重复用户。
- list/get API 默认不返回明文 secret；保存时支持“未修改则保留原值”。
- 认证比较使用恒时比较，日志和错误信息不泄露用户名、密码、UUID 或 token。

### 3.2 非目标

- 第一阶段不实现完整 RBAC、登录账号、管理员/普通用户权限体系。这里的“用户”是代理协议 credential profile，不是操作 yuhaiin 管理页面的登录用户。
- 第一阶段不改变协议线上的认证格式，不修改 SOCKS5、HTTP Basic、VMess UUID、Trojan password 等 wire protocol。
- 第一阶段不把所有 TLS certificate、Reality key、WireGuard peer 公钥等拓扑配置都重构为独立证书库；只抽离真正的 secret，并保留必要的协议结构。
- 第一阶段不要求 SQLite 全库加密。现有数据库已经保存节点和配置明文；可以在后续增加统一 secret-at-rest 加密，但本设计要求至少避免 API/日志再次扩散明文。

## 4. 核心模型

### 4.1 命名

建议代码层使用 user，但模型内部使用“用户凭据类型”区分代理账号和 secret：

~~~text
User = 可被 inbound 自动索引或 outbound 协议引用的一种凭据档案
UserCredential = User 唯一的一种认证材料
UserRef = contract 中只保存的 user ID
~~~

不要让 inbound/outbound 各自定义 Credential，否则后续新增协议时会再次产生转换层。

### 4.2 contract 建议

新增 pkg/contract/user/types.go：

~~~go
type User struct {
    ID         string     json:"id"
    Name       string     json:"name"
    Enabled    bool       json:"enabled"
    Origin     string     json:"origin"       // manual, migrated
    Usage      string     json:"usage"        // inbound, outbound, both
    Credential Credential json:"credential"
}

type Credential struct {
    Type             string                  json:"type"
    Basic            *BasicCredential       json:"basic,omitzero"
    UUID             *UUIDCredential        json:"uuid,omitzero"
    Token            *TokenCredential       json:"token,omitzero"
}
~~~

上面是逻辑结构，实际字段名可以在实现时按现有 tagged-union contract 风格调整。关键约束是：

- 一个 User 只包含一个 credential variant；如果同一个人同时需要 Basic 和 UUID，创建两个 User，名称可以保持相同但 ID 必须不同。
- Credential.Type 必须和具体非 nil variant 一致，且只能存在一个 variant。
- Usage 决定用户是否参与 inbound 自动索引、是否可以被 outbound 选择；由 outbound node 迁移生成的用户默认是 outbound，避免节点认证材料自动成为 inbound 登录凭据。
- secret 字段不能通过普通 list/get response 返回。
- 写入请求和响应分离：UserWrite 可以携带明文；User/UserView 只返回 hasSecret、secret 类型和掩码状态。
- Origin=migrated 的用户由旧配置或旧订阅迁移产生，允许用户重命名和编辑，但不能改变其 ID。

为兼容旧 HTTP/SOCKS5 的“空字段表示通配”语义，Basic credential 建议额外保存匹配策略：

~~~text
username
password
allowAnyUsername
allowAnyPassword
~~~

Basic 的 username/password 必须区分“未提供”和“显式空字符串”：前者表示该 credential 不具备该字段，后者只在 legacy Yuubinsya 等协议中表示有效的空密码。JSON contract 可以使用 `*string`，SQLite 则使用可空 TEXT 列；`allowAny*` 只表示旧配置的通配，不等同于字段缺失。

新建手工用户必须要求 username 和 password 均为明确值，allowAny* 只允许由 legacy migrate 产生，并在 UI 中标记为“兼容旧配置”。这样既能保留旧行为，又不会把空密码误当作新用户的正常安全配置。

建议的 credential 类型：

| 类型 | 字段 | 用途 |
| --- | --- | --- |
| basic | username、password 均可选 | HTTP、SOCKS5、Mixed、SOCKS4A、Yuubinsya、Shadowsocks、ShadowsocksR、Trojan、AEAD、Yuubinsya2 |
| uuid | uuid | VMess、VLESS |
| token | token | Tailscale AuthKey；UI 可显示为 AuthKey |

Basic 是统一的账号凭据：需要用户名和密码的协议同时读取两个字段；只需要用户名的 SOCKS4A 忽略 password；只需要密码的 Yuubinsya、Shadowsocks、ShadowsocksR、Trojan、AEAD 忽略 username。private key 和 peer PSK 不进入本期 User credential。

因此不再保留独立的 `Username`、`Password`、`Secret` credential variant：`Username` 和 `Password` 合并为 `basic.username/basic.password`，原本只有一个 opaque secret 的协议也统一放入 `basic.password`。`Token` 仅用于语义上是 token/AuthKey 的协议；`PrivateKey`、`PreSharedKey` 及 WireGuard/WARP 的设备密钥仍按第 2.2 节保留在协议配置中。一个 User 始终只有一个 Credential variant，需要 Basic 和 UUID 两种材料时创建两个 User。

### 4.3 引用字段

inbound contract 删除 UserIDs。inbound 的认证集合由 AuthCenter 根据协议类型、用户 Enabled 状态和 Usage 自动构建：

~~~text
HTTP/SOCKS5/Mixed -> 所有 Usage=inbound 或 both 且 Basic 具备 username/password，或对应字段启用 allowAny* 的用户
SOCKS4A           -> 所有 Usage=inbound 或 both 且 Basic.username 存在，或启用 allowAnyUsername 的用户
Yuubinsya         -> 所有 Usage=inbound 或 both 且 Basic.password 存在的用户
AEAD transport    -> 所有 inbound/both Basic.password 进入 AuthCenter 的 AEAD key 索引；transport 不保存 UserID
~~~

对 HTTP、SOCKS5、Mixed、SOCKS4A，兼容用户集合为空表示关闭协议层认证，保持当前“用户名和密码都为空时不认证”的行为。HTTP、SOCKS5、Mixed、Yuubinsya2、outbound HTTP 和 outbound SOCKS5 都使用 Basic 的 username/password；SOCKS4A 只取 Basic.username；当前 Yuubinsya、Shadowsocks、ShadowsocksR、Trojan、AEAD 只取 Basic.password。当前 Yuubinsya 即使旧配置的 password 为空也仍是“空密码认证”，不能迁移成 no-auth，必须创建一个 Basic 用户。

transport contract：

~~~go
type AEADTransport struct {
    CryptoMethod string json:"cryptoMethod"
}
~~~

outbound node contract：凡是当前纳入用户管理的认证型协议增加 UserID，并删除或废弃原认证字段：

~~~text
Shadowsocks.Password          -> UserID
Shadowsocksr.Password         -> UserID
Vmess.UUID                    -> UserID
Vless.UUID                   -> UserID
Trojan.Password               -> UserID
Socks5.User/Password          -> UserID
HTTP.User/Password            -> UserID
Yuubinsya.Password            -> UserID
AEAD.Password                -> UserID
Tailscale.AuthKey             -> UserID
~~~

WireGuard.SecretKey、CloudflareWarpMasque.PrivateKey 和 WireGuard Peers[].PreSharedKey 暂不纳入用户管理，继续保留在原 node 配置中。

### 4.4 协议到 credential 的校验矩阵

校验不应散落在前端；建议新增 pkg/user/resolve.go 或 pkg/user/credential.go，集中提供：

~~~go
AuthBasic(username, password string) (Principal, error)
AuthUsername(username string) (Principal, error)
AuthPassword(password string) (Principal, error)
ResolveCredential(userID string, protocolType string) (ResolvedCredential, error)
~~~

| 使用方 | 协议 | 期望 credential | 失败条件 |
| --- | --- | --- | --- |
| inbound | HTTP/SOCKS5/Mixed | basic | 引用不存在、禁用、类型不匹配 |
| inbound | SOCKS4A | basic.username | 没有 username |
| inbound | Yuubinsya | basic.password | 没有 password |
| inbound | AEAD transport | Basic.password 索引 | 没有任何可用 password；具体 key 匹配由 AuthCenter 完成 |
| outbound | Shadowsocks/ShadowsocksR/Trojan/Yuubinsya | basic.password | 没有 password |
| outbound | VMess/VLESS | uuid | UUID 格式非法 |
| outbound | SOCKS5/HTTP | basic | 用户名/密码 credential 不完整 |
| outbound | Tailscale | token | token 为空 |
| outbound | AEAD | basic.password | password 为空 |

## 5. Runtime 设计

### 5.1 AuthCenter

新增一个长期存在的 runtime 服务，例如 pkg/auth.Center：

~~~go
type Center struct {
    store  *store.UserStore
    cache  atomic.Pointer[Snapshot]
}

type Snapshot struct {
    UsersByID          map[string]ResolvedUser
    BasicByUsername    map[string][]Principal
    BasicByPassword    map[string][]Principal
    BasicByPair        map[BasicPair][]Principal
    AEADPasswordKeys   []AEADKey
}
~~~

职责：

1. 从 UserStore 加载用户并构建不可变 snapshot，同时建立按 credential type、Usage 和协议能力过滤的 inbound 索引。
2. 校验 user ID、enabled 状态和 credential 类型。
3. 为 inbound 创建 verifier，为 outbound 解析单个 credential。
4. 用户新增、更新、删除、禁用后原子替换 snapshot 并发布变更事件；inbound 认证通过共享 AuthCenter 即时使用新 snapshot，outbound 因为已经把 secret 注入 dialer，才需要重建受影响 runtime。
5. 在内存中只保留 runtime 所需的解析结果；日志禁止打印解析结果。

各协议包不得直接依赖 store.UserStore 或 SQLite，只接收 AuthCenter 接口：

~~~go
type AuthCenter interface {
    AuthBasic(username, password string) (Principal, error)
    AuthUsername(username string) (Principal, error)
    AuthPassword(password string) (Principal, error)
    NewAEADAuthenticator() (AEADAuthenticator, error)
    ResolveCredential(userID, protocolType string) (ResolvedCredential, error)
}
~~~

协议包只负责解析 wire protocol 并把认证材料交给 AuthCenter。例如 HTTP/SOCKS5 把 username/password 交给 AuthBasic，SOCKS4A 交给 AuthUsername，Yuubinsya 交给 AuthPassword。协议包不查用户表、不判断 Usage、不直接比较密码。

### 5.2 inbound verifier 接入

各协议的 server config 从“明文字段”改为 AuthCenter 接口：

~~~go
type ServerConfig struct {
    Auth AuthCenter
    UDP  bool
}
~~~

具体改造：

- HTTP：收到 Proxy-Authorization 后调用 AuthBasic；AuthCenter 没有匹配用户时返回认证失败。
- SOCKS5：只有配置了 verifier 时才声明/接受 username-password 方法；若无 verifier，才接受 no-auth。当前空用户名/空密码的“部分匹配”行为不再作为新配置语义，迁移时用显式用户保留旧行为的实际结果。
- Mixed：创建 HTTP、SOCKS5、SOCKS4A 时共享同一个 AuthCenter，不要复制一份用户表。
- SOCKS4A：将客户端 username 交给 AuthUsername；恒时比较和多用户查找由 AuthCenter 完成。
- Yuubinsya：旧协议将客户端认证材料交给 AuthPassword；服务端内部的 hash 细节由 AuthCenter/协议适配层统一处理。未来使用 Yuubinsya2 时由 AuthCenter 提供 UserAuth。
- AEAD transport：AuthCenter 根据所有 inbound/both Basic 用户建立 AEADAuthenticator；aead handshaker 在每次握手中通过该 authenticator 尝试匹配密钥。transport contract 不保存 Password，也不保存 UserID。

### 5.3 outbound credential 注入

不要修改每个协议包的底层加密实现。建议在 ContractDialer 之前增加一个解析步骤：

~~~text
Node contract (contains only userId)
        |
        v
AuthCenter.ResolveNode(node)
        |
        v
ResolvedNode (internal, contains runtime-only secret)
        |
        v
ContractDialer / ContractWrap
~~~

有两种实现方式：

1. 推荐：ContractDialer 接收一个 AuthCenter，各 RegisterContractPoint wrapper 在构造 Config 时调用 ResolveCredential。
2. 过渡：在调用 ContractDialer 前把 user ID 展开为内部 config，再调用现有注册逻辑；展开对象只存在内存，不写回 contract。

推荐第一种，因为它能保留节点 contract 的引用语义，避免“展开后又被保存回数据库”的泄漏风险。最终协议构造函数收到的仍然是当前各包需要的 Password、UUID、AuthKey 等运行时字段，因此 Shadowsocks、VMess、Trojan 等底层包不需要知道用户管理。

需要特别处理：

- NetworkSplit.TCP 和 NetworkSplit.UDP 递归解析各自的 user ID。
- Set 只引用 node ID，不直接持有认证材料；实际节点构造时由被选中的 node 解析 user。
- 节点 chain 的同一 user ID 可以被多个协议引用，但每个协议都必须按自己的 credential 类型校验。
- 节点 runtime 创建失败时返回清晰的 user <id> credential type mismatch for protocol <type>，不能只返回“invalid node”。

### 5.4 变更传播与连接生命周期

保存用户不能只更新数据库，必须同时更新 AuthCenter 的原子 snapshot；现有 inbound server 持有的是共享 AuthCenter，而不是一份静态用户表。建议：

~~~text
UserStore.Save/Delete/Disable
        |
        v
AuthCenter atomic snapshot swap
        |
        +--> inbound：共享 AuthCenter，新的握手立即使用新索引
        +--> outbound：关闭旧 dialer，按引用重新构造
        +--> 无 outbound 引用：不重建 dialer
~~~

具体策略：

- 用户的 username/password、UUID 或 token 发生变化时，AuthCenter 更新 snapshot；新的 inbound 握手立即使用新 snapshot，所有引用该用户的 outbound runtime 也需要重建。
- 仅修改用户显示名时不需要重建 runtime。
- 禁用用户时，新的 inbound 握手必须立即失败；已经建立的连接默认不强制踢出，避免在 runtime 热更新过程中破坏现有连接。若后续需要强制断开，应增加显式策略。
- 删除或禁用 outbound 用户时，相关节点应进入不可用状态，不能静默退回 direct。inbound 不保存 user reference，因此禁用/删除用户只需要刷新全局 verifier。
- 用户管理的刷新不能放在保存配置请求中执行远程 I/O；只做 SQLite 写入和本地 runtime 更新。

## 6. Storage 设计

### 6.1 新表

在 pkg/storage/sqlite/migrations.go 增加 schema version 6。由于一个 User 只允许一种 Credential，推荐按 credential 家族拆成少量表，而不是按每个代理协议拆表：

~~~sql
CREATE TABLE users_v2 (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL,
    origin       TEXT NOT NULL DEFAULT 'manual',
    usage        TEXT NOT NULL CHECK (usage IN ('inbound', 'outbound', 'both')),
    credential_type TEXT NOT NULL CHECK (credential_type IN ('basic', 'uuid', 'token')),
    updated_at   INTEGER NOT NULL,
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json))
);

CREATE INDEX users_v2_name_idx ON users_v2(name, id);
CREATE INDEX users_v2_origin_idx ON users_v2(origin);
CREATE INDEX users_v2_enabled_type_usage_idx
ON users_v2(enabled, credential_type, usage);

CREATE TABLE user_basic_v2 (
    user_id            TEXT PRIMARY KEY,
    username           TEXT,
    password           TEXT,
    allow_any_username INTEGER NOT NULL DEFAULT 0,
    allow_any_password INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users_v2(id) ON DELETE CASCADE
);

CREATE INDEX user_basic_v2_username_idx
ON user_basic_v2(username);

CREATE TABLE user_uuid_v2 (
    user_id TEXT PRIMARY KEY,
    uuid    TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users_v2(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX user_uuid_v2_uuid_idx ON user_uuid_v2(uuid);

CREATE TABLE user_token_v2 (
    user_id TEXT PRIMARY KEY,
    token   TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users_v2(id) ON DELETE CASCADE
);

-- 启动迁移的幂等状态和“旧字段来源 -> User”映射
CREATE TABLE user_migration_state_v2 (
    migration_name TEXT PRIMARY KEY,
    status         TEXT NOT NULL CHECK (status IN ('running', 'completed')),
    completed_at   INTEGER
);

CREATE TABLE user_migration_sources_v2 (
    migration_name TEXT NOT NULL,
    source_kind    TEXT NOT NULL, -- inbound, node, subscription_node
    source_id      TEXT NOT NULL,
    source_path    TEXT NOT NULL, -- protocol/http, chain/0, network_split/tcp...
    dedup_scope    TEXT NOT NULL,
    dedup_key      BLOB NOT NULL,
    user_id        TEXT NOT NULL,
    migrated_at    INTEGER NOT NULL,
    PRIMARY KEY (migration_name, source_kind, source_id, source_path),
    FOREIGN KEY (user_id) REFERENCES users_v2(id) ON DELETE RESTRICT
);

CREATE INDEX user_migration_sources_user_idx
ON user_migration_sources_v2(user_id);

CREATE TABLE user_migration_dedup_v2 (
    migration_name TEXT NOT NULL,
    dedup_scope    TEXT NOT NULL,
    dedup_key      BLOB NOT NULL,
    user_id        TEXT NOT NULL,
    PRIMARY KEY (migration_name, dedup_scope, dedup_key),
    FOREIGN KEY (user_id) REFERENCES users_v2(id) ON DELETE RESTRICT
);
~~~

inbound 不保存 user reference，因此不会产生 inbound 的引用表。outbound node contract 仍保存 userId，SQLite 无法直接对 JSON 内引用做 foreign key；如果后续需要高效查询，再增加：

~~~sql
CREATE TABLE user_refs_v2 (
    user_id      TEXT NOT NULL,
    owner_kind   TEXT NOT NULL, -- outbound_node
    owner_id     TEXT NOT NULL,
    owner_path   TEXT NOT NULL,
    PRIMARY KEY (user_id, owner_kind, owner_id, owner_path)
);
~~~

第一阶段可以不引入 user_refs_v2，但必须在保存/删除用户时扫描所有 node contract，并在测试中证明不会产生悬空引用。远程节点较多时建议直接引入引用表，避免每次删除都解码全部 node JSON。

### 6.2 UserStore API

建议新增 pkg/store/user.go：

~~~go
type UserStore struct { db *sql.DB }

func (s *UserStore) List(ctx context.Context) ([]contractuser.UserSummary, error)
func (s *UserStore) Get(ctx context.Context, id string) (contractuser.User, error)
func (s *UserStore) Save(ctx context.Context, user contractuser.UserWrite, updatedAt int64) (contractuser.UserSummary, error)
func (s *UserStore) Delete(ctx context.Context, id string) error
func (s *UserStore) ReferencedBy(ctx context.Context, id string) ([]UserReference, error)
~~~

UserStore 只负责持久化和引用扫描，不向协议包暴露 credential 解析接口。`ResolveCredential`、inbound 索引和所有认证匹配都由 AuthCenter 完成；只有 AuthCenter 的实现可以通过内部 store 读取 secret。

Get 是否返回 secret 需要区分内部接口和 HTTP 接口；推荐内部 GetSecret 只在 runtime 需要时使用，HTTP 使用 UserSummary。保存接口支持：

- replaceSecret=true：使用请求中的 secret 替换旧值。
- replaceSecret=false：请求没有 secret 时保留旧值。
- 显式清空 secret 必须使用 clearSecret=true，避免 UI 因为掩码字段回传而误清空。

### 6.3 备份与恢复

用户数据属于配置的一部分，必须进入现有 SQLite/配置备份范围。恢复顺序建议：

~~~text
users_v2
  -> inbounds_v2 / nodes_v2
  -> runtime rebuild
~~~

恢复时先导入用户，再导入 inbound/node；恢复完成后只对 outbound node 执行全量引用校验。备份上传或日志摘要不得输出 credential 明文；如果已有备份格式会完整导出 data_json，应明确这是当前数据库权限模型下的高敏感备份，并在后续增加加密备份选项。

## 7. HTTP API 与前端 contract

### 7.1 v2 API

沿用当前 POST JSON RPC 体系，新增：

~~~text
users.get             GET  /api/v2/users              -> list summary
users.post            POST /api/v2/users              -> create
user.get              GET  /api/v2/users/{id}         -> summary/detail, no secret
user.put              PUT  /api/v2/users/{id}         -> update
user.delete           DELETE /api/v2/users/{id}       -> delete
user.secret.put       POST /api/v2/users/{id}/secret  -> replace secret, no echo
~~~

如果严格保持现有 route table 的 RPC 风格，前五个应注册为 users.get、users.post、user.get、user.put、user.delete，secret 单独使用 user.secret.put。不要让普通 user.get 返回密码、UUID、token、private key。

摘要响应示例：

~~~json
{
  "id": "user-alice",
  "name": "Alice",
  "enabled": true,
  "origin": "manual",
  "credential": {"type": "basic", "username": "alice", "hasSecret": true},
  "usage": "both",
  "outboundReferences": 3
}
~~~

### 7.2 inbound/node API 变化

- inbound 编辑表单不显示用户选择器，也不显示旧的 username、password、Yuubinsya password 字段；页面只提示“启用的 inbound/both 用户会自动对兼容协议生效”。
- node 编辑表单只显示用户选择器；协议参数如 Shadowsocks method、VMess security/alterID、WireGuard peer endpoint 等仍在协议表单中。
- user selector 根据协议类型过滤 credential 类型，避免选择后才报错。
- API 返回 node contract 时只返回 userId，不返回展开的 user 内容；inbound contract 不再返回 userIds。
- 生成 TypeScript contract 后，src/contract 只保留 UI 默认值和过滤辅助函数，不重新定义整套 user/node/inbound 类型。

### 7.3 删除语义

默认删除用户采用保护模式：

- 如果存在 outbound node 引用，返回 409 user_referenced，响应包括引用数量和 owner 摘要，不包含 secret。inbound 没有显式引用，不会阻止删除。
- 如果用户仍有 `user_migration_sources_v2` 来源映射且兼容窗口内仍保留旧字段，不允许物理删除，只允许禁用或标记 orphan；否则下次启动会根据旧字段再次创建该用户。最终清理阶段删除旧字段和 mapping 后，才允许物理删除。
- UI 必须先移除引用，或者提供明确的“禁用”操作。
- 不建议第一阶段支持强制删除；如果后续增加，必须是显式 force 请求，并同时把引用 owner 标记为 invalid，不得自动改成 no-auth/direct。

## 8. 迁移与兼容策略

### 8.1 contract 兼容窗口

推荐分两阶段：

**阶段 A：读旧写新**

- outbound node contract 增加 userId；inbound contract 不增加 userId/userIds，旧 inbound credential 只转换成全局 User。
- 旧的 username、password、UUID、AuthKey 等字段继续保留在现有结构体中，并标注 `Deprecated`；它们只允许被启动迁移读取，runtime、保存校验和新 API 都不再使用或返回。
- 启动时扫描旧 inbound/node contract，先创建或复用 User，再写入 outbound 的 userId；旧 inbound 不写 userId，只依靠 AuthCenter 的全局索引。
- runtime 只使用新引用字段。

**阶段 B：移除旧字段**

- 所有当前数据库和订阅转换路径完成迁移后，从 contract 和前端表单删除旧字段。
- 旧字段只保留在 legacy migrate package 中，用于一次性导入，不再进入 contract.Inbound/contract.Node。

这样可以避免 Android 旧版本和当前 core 在升级的第一时间因字段缺失而无法启动。

### 8.1.1 deprecated 字段规则

现有结构体暂时不删除旧字段，例如 `inbound.HTTPProtocol.Username/Password`、`inbound.Socks5Protocol.Username/Password`、`node.Socks5.User/Password`、`node.Vmess.UUID`、`node.Tailscale.AuthKey` 等，统一增加注释：

~~~go
// Deprecated: only read by startup user migration; runtime must use AuthCenter.
Username string `json:"username"`
Password string `json:"password"`
~~~

保留字段的目的只是让旧数据库、旧订阅和旧 Android/core contract 可以被解析。新 runtime 构建时必须明确忽略这些字段；新保存路径也不能从这些字段重新生成认证配置。兼容窗口内可以保留旧 JSON 值以支持回滚旧版本，但新 API 不回显，且后续清理阶段再删除存储中的旧值。

### 8.1.2 启动迁移流程

新增独立的 `MigrateLegacyCredentials`，在 UserStore、InboundStore、NodeStore 可用且 runtime 启动前执行：

~~~text
打开 SQLite transaction（BEGIN IMMEDIATE）
        |
读取 user_migration_state_v2；completed 只表示基线已扫描，不代表以后永远跳过新来源
        |
扫描 inbounds_v2、nodes_v2 和订阅节点中的 deprecated 字段，筛选没有 mapping 的来源
        |
规范化 credential -> 计算 dedupScope/dedupKey
        |
按 source mapping 或 dedup mapping 找到/创建 User
        |
写 outbound userId；inbound 只建立全局 User，不写 UserID
        |
写 user_migration_sources_v2 + user_migration_dedup_v2
        |
写 migration state = completed，提交 transaction
        |
AuthCenter reload snapshot，之后才启动 runtime
~~~

迁移必须在同一个 transaction 中完成用户创建、node userId 写入、来源映射和 completed 标记。任意一步失败都回滚；进程在中途退出时下次启动会重新扫描，但不会留下半个 User 或悬空 userId。

已完成迁移后再次启动仍需检查新增的来源，例如新导入的旧订阅节点；`user_migration_state_v2` 只是基线检查点，source mapping 才是每个来源是否迁移过的权威记录。如果某个来源仍有 deprecated 字段但 mapping 已存在且 fingerprint 相同，则跳过，不重复创建用户。若旧版本修改了同一个来源的认证字段，fingerprint 发生变化，则按“来源变更”重新解析、更新 userId/source mapping，并将旧 migrated User 标记为 orphan，不能静默复用旧凭据。新订阅导入、旧格式保存和启动扫描都调用同一个迁移函数，使用同一套 mapping/去重规则。

### 8.1.3 去重规则

去重不能直接使用旧配置所在的 inbound ID 或 node ID，否则同一组用户名/密码会被重复生成。迁移先生成规范化表示，再使用实例级 keyed hash 作为 `dedupKey`；原始 secret 不进入日志、User ID 或错误信息。

规范化表示至少包括：

- credential type；
- 每个字段的“缺失/显式空字符串”状态和值；
- Basic 的 `allowAnyUsername/allowAnyPassword`；
- UUID 的规范化格式；
- token 的完整值；
- 来源隔离 scope。

`dedupScope` 规则如下：

- 本地旧 inbound 和本地手工 outbound 使用同一个 `local` scope；相同 credential 可以合并，并把 User.Usage 合并为 `both`。
- 旧订阅与本地旧配置统一使用 `local` scope；相同 credential 可以复用同一个 User，不再因为来源是订阅而创建另一套用户。
- 同一 source path 优先查 `user_migration_sources_v2`；不同 source path 再查 `user_migration_dedup_v2`。这样既能保证来源级迁移只执行一次，也能保证多个旧配置复用同一个 User。

对于同一 User 同时被 inbound 和本地 outbound 使用，迁移只更新 Usage，不复制 credential。对于 UUID、token 和 Basic 的不同字段组合，即使明文看起来相同，也不能跨 credential type 或字段存在性合并。

### 8.2 旧 inbound 迁移

迁移 pkg/legacy/migrate/inbound.go 和旧 SQLite 恢复逻辑时：

| 旧值 | 新值 |
| --- | --- |
| HTTP username/password 都为空 | 不创建用户，保持 no-auth |
| HTTP 任一字段非空 | 创建 Usage=inbound 的全局 Basic 用户；旧空字段通配语义写入 allowAny*，所有兼容 HTTP inbound 自动生效 |
| SOCKS5 username/password 都为空 | 不创建用户，保持 no-auth |
| SOCKS5 任一字段非空 | 创建 Usage=inbound 的全局 Basic 用户；旧空字段通配语义写入 allowAny*，所有兼容 SOCKS5 inbound 自动生效 |
| Yuubinsya password 非空 | 创建 Usage=inbound 的全局 Basic 用户，保存 password，所有 Yuubinsya inbound 自动生效 |
| Yuubinsya password 为空 | 仍创建 Usage=inbound 的全局 Basic 用户，保存空 password；当前协议是空密码认证，不是 no-auth |
| Mixed 任一字段非空 | 创建 Usage=inbound 的全局 Basic 用户；旧空字段通配语义写入 allowAny*，所有兼容 Mixed 分支自动生效 |
| SOCKS4A username 非空 | 创建 Usage=inbound 的全局 Basic 用户，只保存 username，所有 SOCKS4A inbound 自动生效 |
| AEAD transport password 非空 | 创建 Usage=inbound 的全局 Basic 用户，只保存 password；AEAD AuthCenter 索引自动包含该 key，不写 transport UserID |

迁移用户 ID 必须稳定：优先使用 `dedupScope + dedupKey` 生成 opaque UUID，或在同一 transaction 中生成随机 ID 并依赖 `user_migration_sources_v2` 持久化映射。不能把 password、UUID、token 等原文放进 User ID、名称、日志或 warning。用户名称可以包含原 owner 名称，但不能包含认证材料。

这是有意的兼容取舍：旧 inbound 的认证字段是按 inbound 隔离的，而新模型是全局索引，因此同一旧 credential 在迁移后会对所有兼容 inbound 生效，访问范围可能扩大。若必须保持旧的逐 inbound 隔离，后续需要增加 auth group/scope 与 inbound 绑定；不能通过重新引入每个 inbound 的 UserIDs 来规避本期中心认证模型。

### 8.3 旧 node 迁移

迁移 pkg/legacy/migrate/node.go、订阅 parser 和旧节点 JSON 时：

- 手工 node：使用 `local` dedupScope，按规范化 credential 查找或创建 migrated User，并把协议字段换成 user ID；同一 credential 被多个 node 使用时只创建一次。
- 旧远程订阅 node：与本地旧 node 完全相同，使用 `local` dedupScope，按规范化 credential 查找或创建新的 migrated User；source_kind 使用 `subscription_node` 仅用于启动迁移幂等。
- 订阅刷新只在同一 transaction 中更新 node contract 和 source mapping，不建立远程用户所有权、只读状态或专门垃圾回收流程。
- 不要通过密码明文生成可逆的 user ID；如果需要 fingerprint，只使用带域分隔符的 hash，且不能在日志暴露原文。
- NetworkSplit 的 TCP/UDP 子协议递归迁移；WireGuard peer 的 PSK 继续保留在原 node 配置，不生成 user。

### 8.4 远程订阅处理

远程订阅不再单独设计用户 ownership。所有历史订阅节点都按本地旧节点处理，迁移出的用户写入本地 `users_v2`，`Origin=migrated`，并使用同一套 source mapping、dedupKey 和事务规则。

新格式订阅则更简单：订阅携带的 `userId`、User、Credential、Origin 等用户管理字段全部忽略，不导入远程用户，也不允许远程 userId 直接成为本地引用。订阅导入和刷新只使用本地用户管理中的 User 与本地 node userId：

1. 新订阅节点没有本地 userId 时，标记为缺少凭据，由用户在本地用户管理中选择或创建用户。
2. 订阅刷新不能覆盖本地 User 的名称、凭据、Usage 或 Enabled 状态。
3. 订阅删除或节点替换只处理节点自身；用户是否可删除仍按本地 outbound 引用和迁移 mapping 规则判断。

这样既能把旧订阅中的认证材料一次性迁移到新表，也不会让新的订阅源接管本地用户管理。

## 9. 安全设计

- HTTP API 的 user list/get/put 普通响应禁止返回 secret；错误信息只能包含 user ID/name 和 credential type。
- 密码、UUID、token、private key 不打印到日志、metrics label、connection history 或错误堆栈。
- 验证时使用恒时比较；多个用户查找不能通过错误信息区分“用户名不存在”和“密码错误”。
- AuthCenter snapshot 更新使用原子替换；旧 snapshot 由已有连接安全持有，避免并发 map 写入。
- 禁用用户必须影响新连接；不能只从 UI 隐藏。
- 用户 ID 只能使用系统生成或严格校验的 opaque ID，不能把用户名作为主键，避免改名破坏引用。
- SQLite 文件权限、备份权限和 Android AAR 调用边界需要在实现时重新检查；本方案不把 secret 传到 Android UI 之外的地方，但 core contract 仍然会在内存中持有运行时 secret。
- 兼容窗口内不要求从 inbounds_v2.data_json、nodes_v2.data_json 删除旧认证字段，因为旧结构体和旧 JSON 仍用于回滚迁移；但必须加入扫描测试，确认 runtime 和新 API 不会读取或返回这些 deprecated 字段。最终清理阶段再删除存储中的旧值。

## 10. 错误与行为定义

建议稳定错误码：

| 错误码 | 场景 |
| --- | --- |
| user_not_found | contract 引用不存在的 user ID |
| user_disabled | 引用的用户已禁用 |
| user_credential_type_mismatch | 协议要求 UUID，但用户只有 Basic |
| user_credential_invalid | UUID/key/token 格式非法 |
| user_referenced | 删除仍被引用的用户 |
| user_credential_required | 需要认证材料但没有保存 |

这些错误在保存 contract 时优先返回；runtime 重建时也必须再次校验，防止数据库被外部修改或旧版本写入非法 JSON。

## 11. 测试计划

### 11.1 contract 与 store

- User/credential tagged union 的 marshal/unmarshal、Validate、未知 type、多个 variant 同时存在。
- UserStore CRUD、分页、排序、not found、禁用、secret 不回显。
- SaveNodeContract 在 user ID 不存在或 credential 类型不匹配时失败；SaveInboundContract 不再接受 user ID 或 inline credential 字段。
- 删除有引用的 user 返回 user_referenced；删除无引用的 user 成功。
- schema migration 从 version 5 升到 version 6，重复启动幂等。
- 备份恢复先 users 后 inbounds/nodes，并验证引用完整。
- 启动迁移首次运行会创建用户并写入 source/dedup mapping；第二次运行不新增 User、不重复修改 node contract。
- 迁移 transaction 中途失败或进程退出后重启，能够回滚半成品并安全重试；相同来源、相同 fingerprint 最终只对应一个 User。
- 多个 inbound/node/历史订阅使用相同 credential 时验证去重；所有旧来源共用 local scope；来源 credential 变化时创建/复用新 User 并更新 userId。

### 11.2 inbound 协议行为

每个协议至少覆盖：正确 credential 成功、错误 credential 失败、用户禁用后新连接失败、多个用户其中一个匹配成功。

- HTTP Basic CONNECT 和普通 HTTP request，包括旧配置迁移出的 allowAnyUsername/allowAnyPassword 行为。
- SOCKS5 no-auth/auth-method 协商、TCP、UDP。
- Mixed 的 HTTP、SOCKS5、SOCKS4A 三条分支。
- SOCKS4A username 匹配和不匹配。
- 当前 Yuubinsya TCP、UDP、UDP coalesce，特别验证空密码 credential 仍能与旧客户端互通。
- AEAD transport 的正确/错误 Basic.password。
- TProxy、Redir、Tun、Reverse HTTP、Reverse TCP、None 回归测试，确保无意中被要求 user。

### 11.3 outbound 协议行为

保留各现有协议的 wire tests，并把配置来源从 inline secret 换成 user resolver：

- Shadowsocks/ShadowsocksR/Trojan/Yuubinsya/AEAD 正确 password。
- VMess/VLESS 正确 UUID、非法 UUID、用户类型不匹配。
- HTTP/SOCKS5 正确 username/password 和空 credential 行为。
- Tailscale AuthKey 解析和错误 user。
- WireGuard、Cloudflare WARP MASQUE 的原 inline private key/peer PSK 回归测试，确认本期没有被错误改成 userId。
- NetworkSplit、Set、嵌套 chain、重复 user 引用。

### 11.4 runtime 更新

- 修改显示名不重建 listener/dialer。
- 修改 secret 会立即影响新的 inbound 握手，并重建受影响的 outbound runtime。
- 修改一个用户不影响无引用的 inbound/node。
- 禁用用户不踢出现有连接，但阻止新握手。
- 并发保存用户和连接建立不会出现 data race、旧 snapshot map panic 或明文泄漏。
- go test -race 覆盖 AuthCenter、AEAD 多 key authenticator 和 inbound verifier。

### 11.5 迁移回归

- 现有 legacy inbound 的五种认证协议迁移后 wire 认证行为保持一致；全局用户索引导致旧的逐 inbound 访问隔离按第 8.2 节的取舍处理。
- 现有 legacy node 的所有认证协议迁移后仍能建立客户端。
- 远程订阅刷新不会重复生成用户，也不会删除仍被新节点引用的用户。
- 启动迁移重复执行不会重复创建用户，`user_migration_state_v2`、source mapping 和 dedup mapping 保持一致。
- Android/core 启动时旧数据库可以完成迁移；缺少 Java 时 Android 侧至少执行静态 contract/schema 检查，Go core 执行完整测试。

## 12. 实施阶段

### Phase 1：模型与持久化

1. 新增 contract/user、store.UserStore、SQLite migration。
2. 保留现有协议结构体的认证字段并标记 Deprecated，增加启动迁移状态、来源映射和去重索引。
3. 实现启动时 transaction 化的 legacy credential migration，再增加 User CRUD API 和 generated TypeScript contract。
4. 实现 secret 不回显、引用扫描和类型校验。

### Phase 2：inbound

1. 保留 HTTP/SOCKS5/Mixed/SOCKS4A/Yuubinsya 以及 AEAD transport 的旧认证字段并标记 Deprecated；runtime 忽略它们，inbound 不增加 UserIDs，并增加由 AuthCenter 提供的 authenticator 注入点。
2. 改造 HTTP/SOCKS5/Mixed/SOCKS4A/Yuubinsya server config 为 verifier/secret resolver。
3. 接入 AuthCenter，完成全局兼容用户索引和用户变更后的 inbound rebuild。
4. 完成旧 inbound/node 启动迁移、去重和重复启动幂等测试。

### Phase 3：outbound

1. 给纳入用户管理的认证型 node protocol 增加 UserID；WireGuard、Cloudflare WARP MASQUE 和 WireGuard peer PSK 保持原 inline 字段。
2. 在 ContractDialer/ContractWrap 构建链路接入 AuthCenter.ResolveCredential。
3. 完成手工 node、远程订阅和 legacy node 的迁移。
4. 完成 outbound runtime rebuild。

### Phase 4：前端与 Android

1. 增加用户管理页面、secret 掩码编辑、协议类型过滤选择器。
2. inbound/node 表单去除旧 credential 输入。
3. 更新 generated client 和 contract 组合层。
4. Android 若直接构造 contract，需要同步 user API、字段和迁移版本；核心逻辑仍以 Go core 为唯一认证实现。

### Phase 5：移除旧字段

1. 监控一段兼容窗口内旧字段的读写次数。
2. 确认所有数据库和订阅路径完成迁移，并确认旧版本回滚窗口结束。
3. 再删除新 contract 中的旧明文字段，只在 legacy migrate 保留兼容转换。
4. 清理历史 JSON 中的旧字段，并增加扫描断言，禁止新保存的 node/inbound JSON 出现旧字段。

## 13. 推荐的最终边界

最终数据流应当是：

~~~text
                    +----------------------+
                    |      UserStore       |
                    |  users_v2 + secrets  |
                    +----------+-----------+
                               |
                         AuthCenter
                   +-----------+-----------+
                   |                       |
          inbound verifier        outbound resolver
                   |                       |
       HTTP/SOCKS/Yuubinsya       ContractDialer chain
                   |                       |
               net server         protocol client configs

inbound contract ------------------- no user references
outbound node contract ------------- only userId
~~~

最重要的实现原则是：

1. contract 只保存引用，runtime 才解析 secret。
2. protocol 包只负责 wire protocol，不负责查数据库。
3. AuthCenter 负责 credential 类型校验、全局 inbound 索引、快照和变更通知。
4. protocol 包只能调用 AuthCenter，不能读取 UserStore、SQLite 或自行比较 credential。
5. store 负责引用完整性，API 负责 secret 脱敏，前端只为 outbound 提供选择器。
6. 迁移必须先创建用户，再替换 outbound 引用；任何解析失败都不能自动降级为无认证、direct 或其他用户。
