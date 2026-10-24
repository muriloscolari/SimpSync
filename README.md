# 🔄 SimpSync (Zero-Knowledge Cloud Sync Backend)

O **SimpSync** é o servidor de sincronização em nuvem seguro com criptografia de ponta a ponta (**E2EE - Zero-Knowledge**) projetado especificamente para o SimpMusic.

O servidor foi arquitetado para ser auto-hospedado (*self-hosted*), altamente eficiente em memória/armazenamento e resistente a ataques de negação de serviço (DoS) e exaustão de recursos (OOM).

---

## 🔐 Como Funciona a Criptografia (Zero-Knowledge E2EE)

1. **Derivação de Chaves no Cliente**:
   - A senha do usuário **nunca** chega ao servidor.
   - O aplicativo deriva no cliente uma chave de autenticação (`authProof`) e uma chave mestra de desembrulho (`wrappingKey`) usando **PBKDF2-HMAC-SHA256** (120.000 iterações com salt do email).
2. **Criptografia Simétrica (AES-256-GCM)**:
   - Uma chave de dados (`DEK` de 256 bits) é gerada aleatoriamente no primeiro registro.
   - Todas as entidades (músicas curtidas, playlists, configurações, histórico) são criptografadas com `AES-256-GCM` antes de saírem do seu dispositivo.
3. **Chaveiro Duplo com Recovery Key**:
   - A `DEK` é envelopada e salva no servidor de duas formas:
     - Envelopada pela sua **Senha Mestra**.
     - Envelopada por uma **Chave de Recuperação (Recovery Key)** (`XXXX-XXXX-XXXX-...`).
   - Se você esquecer a senha, a chave de recuperação permite restabelecer sua conta e descriptografar toda a biblioteca sem perder nada.
4. **O Servidor Não Sabe Nada**:
   - O PostgreSQL armazena apenas blobs binários opacos (`envelope`), versões incrementais e timestamps. O servidor não tem acesso aos nomes das músicas, artistas ou playlists.

---

## ⚡ Sincronização em Tempo Real (WebSocket + Invalidation Tracker)

- **Envio Quase Instantâneo (~1.5s)**: Ações principais da biblioteca (curtir/descurtir músicas ou álbuns, seguir artistas, criar ou editar playlists locais) disparam envio automático em ~1.5 segundo (*debounce* inteligente para agrupar cliques rápidos).
- **Recepção em Tempo Real (~300ms)**: Assim que um dispositivo envia uma alteração, o servidor emite uma notificação leve via WebSocket para todos os outros dispositivos autenticados da conta, que puxam os dados e atualizam as telas da biblioteca de forma silenciosa.
- **Histórico e Estatísticas Otimizados**: A reprodução contínua e eventos de Analytics são enviados em lotes a cada 5 minutos, garantindo impacto nulo de CPU e gravação no SSD.

---

## 🛡️ Camada de Segurança e Blindagem do Servidor

O backend em Go foi totalmente auditado e protegido contra vazamento de memória e ataques:

- **Semáforo Concorrente de Argon2id**: No servidor, os hashes de autenticação usam Argon2id limitado a no máximo **2 verificações simultâneas** (teto fixo de 128 MB de RAM para evitar ataques de esgotamento de memória/OOM).
- **Rate Limiting em Memória por IP**: Algoritmo Token Bucket limitado a no máximo 4096 IPs monitorados simultaneamente com limpeza automática periódica (TTL sweep).
- **Bloqueio de Registro (Anti-Abuso)**: Suporte a `ALLOW_REGISTRATION=false` e `MAX_USERS=1` para garantir que ninguém mais registre contas no seu servidor pessoal.
- **WebSockets Protegidos**: Rotinas dedicadas `readPump` e `writePump` com limite de buffer de 4 KB, detecção de queda via Ping/Pong (30s) e limite máximo de 10 dispositivos por usuário.
- **Container Hardened**:
  - Usuário não-root (`uid=10001:10001`).
  - Sistema de arquivos somente leitura (`read_only: true`).
  - Descarte total de capacidades do Linux (`cap_drop: [ALL]`).
  - Limite de memória física no Compose (`mem_limit: 512m`).
  - Porta exposta restrita exclusivamente a `127.0.0.1:8787` (atrás de proxy reverso Nginx com SSL).

---

## 🚀 Como Subir o Servidor (Passo a Passo)

### 1. Pré-requisitos
- Docker e Docker Compose instalados no servidor.
- Nginx com certificado SSL (ex: Certbot/Let's Encrypt).

### 2. Configurar Variáveis de Ambiente
Na pasta do SimpSync, copie o exemplo e gere suas chaves secretas:

```bash
cd /caminho/para/SimpSync
cp .env.example .env
```

Edite o arquivo `.env`:
```env
PORT=8787
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=simpsync
POSTGRES_PASSWORD=coloque_uma_senha_forte_aqui
POSTGRES_DB=simpsync
AUTH_PEPPER=gere_com_openssl_rand_hex_32
ALLOW_REGISTRATION=true
MAX_USERS=1
RATE_LIMIT_RPS=5
RATE_LIMIT_BURST=10
CLEANUP_INTERVAL_HOURS=24
```

> **Dica de Segurança**: Gere o `AUTH_PEPPER` no terminal com:
> ```bash
> openssl rand -hex 32
> ```

### 3. Iniciar os Containers
```bash
docker compose up -d --build
```

Verifique se os containers subiram corretamente:
```bash
docker compose logs -f server
```

### 4. Configurar o Proxy Reverso (Nginx)
Adicione ao seu Nginx (ex: `/etc/nginx/sites-available/simpsync`):

```nginx
server {
    server_name sync.seudominio.com;

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;

        # Suporte a WebSockets
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

Recarregue o Nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 5. Fechar Novos Registros Após Criar Sua Conta
Assim que você registrar sua conta pelo aplicativo (no Desktop ou celular), edite o `.env`:
```env
ALLOW_REGISTRATION=false
```
E reinicie o container:
```bash
docker compose up -d server
```

---

## 📱 Como Conectar no Aplicativo (Desktop & Android)

1. No **SimpMusic**, abra **Configurações**.
2. No grupo **Dispositivos** (no topo), toque em **SimpSync Cloud (E2EE)**.
3. No campo **URL do Servidor**, informe seu domínio com HTTPS (ex: `https://sync.seudominio.com`).
4. **Primeiro Acesso**:
   - Mude para a aba **Cadastrar**.
   - Informe seu e-mail e crie uma senha.
   - **IMPORTANTE**: Guarde a **Chave de Recuperação (Recovery Key)** exibida na tela.
5. **Nos Demais Dispositivos**:
   - Vá na aba **Entrar**, informe a URL, seu e-mail e senha.
   - A biblioteca, favoritos e playlists sincronizarão imediatamente.

---

## 🛠️ Comandos Úteis de Manutenção

- **Ver logs em tempo real**:
  ```bash
  docker compose logs -f server
  ```
- **Consultar quantidade de dados sincronizados no Postgres**:
  ```bash
  docker compose exec postgres psql -U simpsync -d simpsync -c "SELECT entity_type, count(*) FROM sync_blob GROUP BY entity_type;"
  ```
- **Rodar a suíte de testes de concorrência e vet**:
  ```bash
  go test -race -v ./...
  go vet ./...
  ```
