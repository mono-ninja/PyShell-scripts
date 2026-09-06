# Аудит CSP

Наскільки міцний Content-Security-Policy насправді — глибокий розбір
за рядком присутності в Security Headers: **unsafe-inline/unsafe-eval**
у script-src (прямо чи успадковано з default-src) з нюансом нонса
(поруч із нонсом сучасні браузери ігнорують unsafe-inline —
звітується як перехідна форма), **вілдкарди** (`*`, схеми, `*.sub`),
**хости-обходи** — пункти allowlist, які можуть віддавати
атакувальний чи довільний скрипт (unpkg, jsdelivr,
raw.githubusercontent, сімейство JSONP, публічні бакети) з
курованого YAML з причинами, відсутні **фундаменти** (base-uri,
object-src, frame-ancestors зі звіркою проти X-Frame-Options,
form-action, upgrade-insecure-requests), **strict-dynamic** і
**двійник Report-Only**, зведений з чинною політикою.

Один запит; кожна знахідка називає директиву і джерело.

---

## Перед запуском

1. Введіть **URL** сторінки, CSP якої розбираємо.
2. **Prepare Env** — встановлює `requests` і `pyyaml`.
3. Натисніть **Run** (⌘↩).

## Поля

### Target

- **URL** — сторінка. Обидва заголовки читаються з однієї
  відповіді: чинний `Content-Security-Policy` і його двійник
  `Content-Security-Policy-Report-Only`, коли він є.
- **Per-request timeout (s)** — 3–60, типовo 15.

---

## Результат

- **Вкладка Results** — таблиця (серйозність · перевірка · деталь)
  і звіт:
  - **unsafe-inline / unsafe-eval / wildcard / bypass-host /
    base-uri / object-src / frame-ancestors / form-action /
    upgrade-insecure-requests / strict-dynamic / nonce** — кожна
    перевірка з причиною і директивою, до якої належить;
    успадкування з default-src називається
    (`default-src→script-src`).
  - **Двійник Report-Only** — diff: джерела, толеровані в
    Report-Only, але заблоковані чинною політикою (форма
    «звітуюте те, що вже запобігаєте», чи «приглядаєтесь до
    послаблення»), і навпаки — чинне, але відсутнє у звіті.
  - **Форма, до якої прагнути** — нонс + strict-dynamic,
    фундаменти-однорядки, Report-Only як стан випробування, ніколи
    як постійний.
- **Артефакти** — `report.md`, `findings.json` (розпарсена політика
  включно, машиночитно).

### Вердикти

🔴 script-src wide open · 🟠 holes to close · 🟢 strict · 🟡
present, plain. Коли сторінка взагалі без CSP — код 1 з вказівкою
на Security Headers (який оцінює саму відсутність).

## Коди виходу

| Код | Значення |
|---|---|
| 0 | відпрацювало; звіт і є картина |
| 1 | недосяжно, або заголовка CSP взагалі нема |
| 2 | помилкові аргументи: URL без http(s) |

## Пов'язане

- **Security Headers** — оцінки за наявність; цей скрипт — глибокий
  розбір за його рядком CSP.
- **CORS Check** — інший брат-глибокорозбірник (сімейство
  Access-Control).
- **Web Conf Audit** — сторона конфіґа: де живе цей add_header.
