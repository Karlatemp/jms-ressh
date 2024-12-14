# JumpServer ReSSH Agent

此项目用于自动处理 JumpServer 的 ssh 二次验证要求, 以用于将其桥接至另一个 JumpServer

附带 Socks5 SSH JumpProxy 功能

## 备注

主服务端口为 7411 <br/>
SSH Socks5 ProxyJump 端口为 7341

建议使用 docker compose

```yaml
services:
  app:
    image: azul/zulu-openjdk:21-latest
    ports:
      - 7411:7411
      - 7341:7341
    restart: always
    volumes:
      - ./bin:/app/bin:ro
      - ./data:/app/data:rw
    working_dir: /app
    command: java -jar ./bin/jms-ressh-1.0-SNAPSHOT-all.jar
```

## 配置

### 主模块

```text
/data/user/<xxxx>/
    # xxxx 对外的登录账户名
    /authorized_keys
        # 同 .ssh/authorized_keys
    /settings.properties
        authorization.password: 对外的连接密码, 留空 / 删除禁用密码登录
        remote.user: 远端用户名
        remote.host: 远端主机名
        remote.port: 远端端口
        remote.password: 远端密码, 可留空
        remote.totp: TOTP Secret
    /keys/<?????>
        # keys 目录下的所有文件均视为连接远程服务器所使用的密钥
        # 可以将 .ssh/id_xxxx 复制到此文件夹（私钥）
```

### Socks5 ProxyJump

此模块通过将 PortForward 请求桥接至 Socks5 服务以允许 JumpServer 通过 socks5 访问服务器

```text
/data/socks/
    /authorized_keys
        # 同 .ssh/authorized_keys
    /settings.properties
        enable: 为 true 时开启此子模块
        port: 子模块端口，没有配置时默认为 7341
        auth.password: 连接密码
        auth.noauth: 为 true 时不需要密码即可连接
        socks5.host: Sock5 主机
        socks5.port: Sock5 端口
```

> 连接测试: `ssh -J localhost:7341 root@192.168.1.1`

> 将 `Socks5 ProxyJump` 服务器的地址作为 `主机 / Gateway` 类型添加至 JumpServer, 并绑定至网域内即可令 JumpServer 以此代理连接远程服务器

