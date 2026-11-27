# Amnezia Panel

Self-hosted control panel for AmneziaWG, WireGuard and OpenVPN. Проект находится на ранней стадии разработки.

## Статус

Начальный каркас: монорепозиторий с TypeScript/Express API и React/Vite UI. Пока нет production-интеграции с Docker, официальными контейнерами Amnezia или подтверждённой совместимости формата `vpn://`.

## План

Полный перевод исходного плана: [`ПЛАН-РАЗРАБОТКИ.md`](./ПЛАН-РАЗРАБОТКИ.md).

## Структура

- `server/` — API, авторизация, криптография и runtime-адаптеры.
- `web/` — React-интерфейс.
- `deploy/` — будущие Docker и VPS-установочные файлы.

## Разработка

Требуется Node.js 22+ и npm.

```bash
cd server && npm install && npm run dev
```

В другом терминале:

```bash
cd web && npm install && npm run dev
```

Не выставляйте API наружу до настройки TLS, секретов, ограничений доступа и проверки безопасности.
