# Аудит GHA

Що workflows GitHub Actions справді дозволяють —
`.github/workflows/*.yml`, прочитані пасивно: **екшени на тегах**
(форма tj-actions: мутабельні refs, які можна перенацілити будь-коли;
SHA/локальні/docker розпізнаються), **pull_request_target**
(секрети репо на подіях PR; з checkout-ом голови PR — критична
форма ексфільтрації), **інтерполяція подій у run:** (ін'єкція
команд, де автор PR тримає ручку), **секрети в логи** (echo
`${{ secrets.* }}`, дампи printenv/env), **self-hosted ранери**,
**обсяги permissions** (відсутній блок, write-all, зайві права на
рівні job) і **workflow_run** (токени на подіях, які ви не
набирали).

Третій пасивний аудит конфігів після fw-audit і web-conf-audit;
нічого не виконується, нічого не надсилається на GitHub.

---

## Перед запуском

1. Оберіть **Repository folder** — корінь репо з
   `.github/workflows`, або теку з файлами workflows напряму;
   **Recursive** (типово увімкнено) знайде ще workflows-теки в
   монорепо.
2. **Prepare Env** — встановлює `pyyaml`.
3. Натисніть **Run** (⌘↩).

## Поля

### Input

- **Repository folder** — кожен `.yml`/`.yaml` у
   `.github/workflows` (плюс вільні workflow-YAML у самій теці).
- **Recursive** — обхід дерева в пошуку інших
   `.github/workflows`.

---

## Результат

- **Вкладка Results** — таблиця (серйозність · перевірка · файл ·
  job · деталь) і звіт, згрупований по файлах workflows:
  - **🔴 injection / pull_request_target-з-checkout** — форми, що
    ексфільтрують секрети вже сьогодні.
  - **🟠 pinning / permissions / self-hosted / secrets-echo /
    pull_request_target** — умови, що роблять червоні форми
    можливими або підготують витік на завтра.
  - **ℹ️ workflow_run / відсутній permissions / printenv** — варто
    глянути.
  - **Безпечні форми** — SHA-піни, `read-all` + розширення по
    одному job, env-опосередкування для недовірених даних.
- **Артефакти** — `report.md`, `findings.json`.

## Коди виходу

| Код | Значення |
|---|---|
| 0 | відпрацювало; знахідки — результат |
| 1 | під текою нема файлів workflows |
| 2 | помилкові аргументи: не тека |

## Пов'язане

- **secret-scan** — що вже витікло в дереві; **dep-audit** —
  лок-файли поруч із workflows.
- **fw-audit / web-conf-audit** — братні пасивні аудити конфігів
  (firewall, веб-сервер).
