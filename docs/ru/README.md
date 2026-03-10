# Документация WolfGuard

![Documents](https://img.shields.io/badge/Documents-11-34a853?style=for-the-badge)
![Language](https://img.shields.io/badge/Lang-Русский-ea4335?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

> Техническая документация для **WolfGuard** -- VPN-сервер на C23, реализующий протокол OpenConnect с wolfSSL, io_uring и нативными механизмами безопасности Linux.

---

## Карта документации

```mermaid
graph TD
    IDX["docs/ru/README.md<br/>(Вы здесь)"]

    subgraph "Архитектура"
        A1["01-architecture.md<br/>Архитектура"]
        A2["02-protocol.md<br/>Протокол OpenConnect"]
    end

    subgraph "Криптография и безопасность"
        B1["04-tls-dtls.md<br/>TLS и DTLS"]
        B2["07-security.md<br/>Безопасность"]
    end

    subgraph "Эксплуатация"
        C1["03-configuration.md<br/>Конфигурация"]
        C2["05-authentication.md<br/>Аутентификация"]
        C3["06-deployment.md<br/>Развёртывание"]
    end

    subgraph "Справочник"
        D1["08-development.md<br/>Разработка"]
        D2["09-rfc-compliance.md<br/>Соответствие RFC"]
        D3["10-monitoring.md<br/>Мониторинг"]
        D4["11-cli-reference.md<br/>Справочник CLI"]
    end

    IDX --> A1
    IDX --> B1
    IDX --> C1
    IDX --> D1

    A1 --> A2
    A2 --> B1
    B1 --> B2
    C1 --> C2
    C2 --> C3
    C3 --> D3
    D1 --> D2
    D4 --> D3

    style IDX fill:#1a73e8,color:#fff
```

---

## Содержание

### Архитектура

| # | Документ | Описание |
|---|---|---|
| 01 | [**Архитектура**](./01-architecture.md) | Трёхпроцессная модель, io_uring, проектирование IPC |
| 02 | [**Протокол OpenConnect**](./02-protocol.md) | Туннель CSTP/DTLS, формат пакетов, процесс рукопожатия |

### Криптография и безопасность

| # | Документ | Описание |
|---|---|---|
| 04 | [**TLS и DTLS**](./04-tls-dtls.md) | Интеграция wolfSSL, наборы шифров, DTLS 1.2 |
| 07 | [**Безопасность**](./07-security.md) | wolfSentry, seccomp, Landlock, усиление nftables |

### Эксплуатация

| # | Документ | Описание |
|---|---|---|
| 03 | [**Конфигурация**](./03-configuration.md) | Справочник TOML-конфигурации, JSON-правила, переменные окружения |
| 05 | [**Аутентификация**](./05-authentication.md) | PAM, RADIUS, LDAP, TOTP, архитектура sec-mod |
| 06 | [**Развёртывание**](./06-deployment.md) | systemd, контейнеры, продуктивная среда |

### Справочник

| # | Документ | Описание |
|---|---|---|
| 08 | [**Разработка**](./08-development.md) | Система сборки, тестирование, конвенции C23, инструментарий |
| 09 | [**Соответствие RFC**](./09-rfc-compliance.md) | Матрица соответствия RFC, заметки по реализации |
| 10 | [**Мониторинг**](./10-monitoring.md) | Метрики Prometheus, структурированное логирование, оповещения |
| 11 | [**Справочник CLI**](./11-cli-reference.md) | Команды iogctl, форматы вывода, REST API |

---

*Последнее обновление: 2026-03-08*
