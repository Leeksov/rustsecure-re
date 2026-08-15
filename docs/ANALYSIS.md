# RustSecure.exe — Полный анализ (реверс-инжиниринг)

> **Правило безопасности (от пользователя):** бинарь **НИКОГДА НЕ ЗАПУСКАТЬ**.
> Вся работа — только статический анализ метаданных/IL. Деобфускация — только
> эмуляция в Python, без выполнения кода бинаря.

---

## 1. Что это за программа

Файл `RustSecure.exe` — это **.NET-приложение (PE/CLR)**, на самом деле представляющее
собой **загрузчик античит-системы для игры Rust**
под «анти-чит» (RustSecure).

Функциональность (восстановлена по сигнатурам методов и строкам):

| Область | Описание |
|---|---|
| **HWID-лицензирование** | Привязка к железу, ключи, проверка лицензии |
| **Steam / OAuth-токен аутентификация** | Логин через Steam/OAuth |
| **Анти-отладка / анти-VM** | `CheckDebugPort`, `DetachFromDebuggerProcess`, `HideOsThreads`, `isVM_by_wim_temper`, `IsServerOS` |
| **Загрузка payload с бэкенда** | `DownloadAndDecryptPayload`, `LogEndpointDiagnostics`, `LogWebExceptionResponse` |
| **Расшифровка payload** | `DecryptPayload`, `ComputeSignature`, `HmacSha256`, `AesEncryptCbc` |
| **Ручная инъекция DLL в процесс Rust** | `Inject`, `StartRustClient`, `WaitForModule`, `CloseExistingRustClientsHard`, `RemoteLoadModule`, `InvokeDllEntryLikeRemote`, `ResolveImports`, `PerformRelocations`, `RvaToOffset` |
| **UI / оверлей** | `DrawOverlay`, `DrawProgress`, `LoadBackground`, `LoadEmbeddedFont`, `OnPaint` |

**Вывод:** античит с серверной выдачей payload
(зашифрованная DLL), HWID-лицензией и ручной инъекцией в `Rust`.

---

## 2. Метод обфускации (разобран полностью)

Бинарь обфусцирован коммерческим обфускатором .NET (признаки: переименование в
«склеенные имена BCL API» типа `SystemInfoEnable`, `MonthTokenOptionalFieldAttribute`,
`GetChannelDataRaiseDeserializationEvent`, `NumLocalTimeMarkgetShadowCopyFiles` —
характерно для **Agile.NET / SecureTeam CliSecure**-семейства, версия с виртуализацией).

Обфускация состоит из **4 слоёв**:

### 2.1. Переименование всего (junk names)
Имена типов/методов заменены на конкатенации настоящих имён BCL API. Восстановить
логику можно только по сигнатурам вызовов (MemberRef) и паттернам.

### 2.2. Шифрование строк (AES-256-CBC)
- Все строки (URL бэкенда, Telegram, пароли, `sharedSecret` и т.д.) зашифрованы
  **AES-CBC**, закодированы **Base64** и лежат:
  - в таблице FieldRVA (см. §4) и/или
  - одной сплошной newline-таблице по файловому смещению **0x2D0385** (≈112 строк,
    44 base64-символа = 32 байта = 2 блока AES).
- Дешифровка (по кластеру стабов 0x08BF–0x08DF):
  `Aes::Create → set_Key → set_IV → CreateDecryptor → CryptoStream(FromBase64String(ct), ...) → читать`.
- Ключ/IV **вычисляются виртуальной машиной** (см. §2.3) из FieldRVA-таблиц —
  это и есть главный нерешённый пункт (см. §5).

### 2.3. Виртуализация методов (VM)
Самый сильный слой. Структура:
- **Делегат-массивы** — статические поля `IntPtr[]`, заполненные через `ldftn`
  указателями на «обработчики» (stub-методы). Диспетчеризация через `calli`.
- **Байткод** — последовательность опкодов в FieldRVA-полях (см. §4, поля 1427–1436).
- **Таблица узлов** — дерево (binary-search) в FieldRVA-полях, используется для
  поиска значений по индексу.
- **Интерпретатор** — «tree-walking»/стековая машина: читает байт-опкод (1–14),
  диспетчеризует в обработчик через `delegate_array[operand]`, оперирует стеком
  `object[]` (локальная переменная), читает/пишет узлы таблицы.

Пример диспетчерского фрагмента (метод `xDTMQZeZocSY` 0x89C):
```
ldsfld  FLD[1007]          ; делегат-массив обработчиков
ldloc   <bytecode_ptr>     ; указатель в байткод (FLD[1427])
ldloc   local(3)           ; = 4 (sizeof int)
add
ldind.i4                   ; operand = *(int*)(ptr+4)
ldelem.i                   ; delegate_array[operand]
calli   0x11000149         ; вызов обработчика
```

### 2.4. Дробление методов (method splitting)
Тысячи крошечных stub-методов, каждый из которых делает **один** BCL-вызов:
`ldarg; call <MemberRef>; ret`. Это размазывает вызовы по всему бинарю и убивает
наивный контроль потока.

---

## 3. Крипто-архитектура (3 группы)

Найдено 68 крипто-stub методов (по их MemberRef-вызовам):

| Группа | Стабы (RID) | Назначение |
|---|---|---|
| **1. Логирование** | 0x00CD–0x00F1 | AES encrypt + SHA256 + HMAC (шифрование логов) |
| **2. Payload** | 0x039A–0x03CA | AES decrypt + HMAC-SHA256 (расшифровка DLL) |
| **3. Строки** | 0x08BF–0x08DF | AES decrypt + Base64 + CryptoStream (строки) |

Ключевые стабы группы 3 (внутри делегат-массива FLD[1009]):
- FLD[1009][8]  = MD[2239] → `Aes::Create` (стаб 0x08BF)
- FLD[1009][11] = MD[2242] → `set_Key` (стаб 0x08C2)
- FLD[1009][13] = MD[2244] → `set_IV` (стаб 0x08C4)
- FLD[1009][14] = MD[2245] → `get_Key`
- FLD[1009][15] = MD[2246] → `get_IV`
- FLD[1009][16] = MD[2247] → `CreateDecryptor`
- FLD[1009][17] = MD[2248] → `FromBase64String`
- FLD[1009][19] = MD[2250] → `CryptoStream::ctor`
- FLD[1013][2]  = MD[2271] → `Encoding::GetBytes` (стаб 0x08DF)

---

## 4. Ключевые артефакты (координаты для дальнейшей работы)

### 4.1. Делегат-массивы (обработчики VM)
Сохранены в `delegate_map.json` (209 полей-массивов, 1907 слотов).
Связанные со строковой VM:
- **FLD[1007]** — 4 слота (MD 2211–2214) — базовые примитивы VM.
- **FLD[1008]** — 13 слотов (MD 2217–2229).
- **FLD[1009]** — 31 слот (MD 2231–2261) — главный набор крипто-обработчиков.
- **FLD[1010]**, **FLD[1011]**, **FLD[1012]** — по 1 слоту.
- **FLD[1013]** — 3 слота (вкл. `Encoding::GetBytes`).

### 4.2. FieldRVA-таблицы VM (10 полей = 5 пар «байткод + дерево»)
Поля 1427–1436. Пара = (байткод, таблица узлов):
- 0x89C `xDTMQZeZocSY` → FLD[1427] (байткод, 137 байт), FLD[1428] (дерево, 224 байта)
- 0x89D `EtIVieiKlEhE` → FLD[1429], FLD[1430]
- 0x89E `awhuBmgthIGH` → FLD[1431], FLD[1432]
- ... (кластер 0x89C–0x8A2, 7 методов, каждый дешифрует одну строку в FLD[1005]/FLD[1006])

Байткод FLD[1427] — поток 8-байтных инструкций: `[опкод:1 байт][3 байта][operand:int32]`,
опкоды 1–14, operand = индекс в FLD[1007].
Таблица FLD[1428] — дерево: записи по 24/48 байт со смещениями 0/8/16/24/32/40,
доп. подтаблицы на +80 и +152; значения-листья: `0x30, 0x02, 0x51, 0x12, 0x12, 0x3F,
0x30, 0x51, 0x38, 0x51, 0x51, 0x2E, 0x7F, 0x0A`.

### 4.3. Таблица зашифрованных строк
- Файловое смещение **0x2D0385**, ≈112 Base64-строк (по 44 симв.), newline-разделены.
- Расшифровка = AES-CBC. Ключ/IV найдены (см. §6.4) — собираются VM из таблиц
  (FieldRVA), а не лежат готовым куском в бинаре.

### 4.4. Встроенная DLL (payload)
- Ресурс `fMqF9GK0sigFT7melZ` — зашифрованная DLL (payload для инъекции в Rust).
- Расшифровывается группой 2 (AES decrypt + HMAC-SHA256).

### 4.5. Инструменты (в `re_analysis/`)
| Файл | Назначение |
|---|---|
| `deobfuscator.py` | Stage 1: строит `delegate_map.json` (поле → слоты) |
| `delegate_map.json` | карта делегат-массивов (результат) |
| `dump_il.py` | дамп IL метода по имени |
| `dump_fieldrva.py` | дамп всех 380 FieldRVA-полей |
| `trace_key.py` | трассировка ссылок на поля строковой VM |
| `crypto_stubs.py` | список крипто-стабов |
| `crack_base64.py` / `crack_strings.py` | попытки подбора ключа (пока без успеха) |

---

## 5. Задачи (все выполнены)

1. ~~**Эмуляция VM**~~ ✅ — ключ/IV извлечены (см. §6.4).
2. ~~**Расшифровать строки**~~ ✅ — 347 строк расшифровано (`solve_strings.py`).
3. ~~**Расшифровать DLL**~~ ✅ — core.enc (19MB managed) + native.enc (39KB x64).
4. ~~**Обход**~~ ✅ — 13 детекторов задокументированы в `bypass/`.

---

## 6. Технические детали (чтобы не потерять)

### 6.1. dnfile API (важно)
- `FieldRva.Field.row_index` = RID поля; `.row` = FieldRow; `.Rva` = RVA.
- `Field.Name` = `HeapItemString` → `.value` → bytes → decode.
- `ClassLayout.Parent.row_index` = TypeDef RID; `.ClassSize` = размер.
- `ManifestResource.Offset` = RVA.
- Файловое смещение = `.text.PointerToRawData + (rva - .text.VirtualAddress)`.
- Размер FieldRVA-поля = разница RVA соседних полей (подтверждено: 380 ClassLayout == 380 FieldRVA 1:1).

### 6.2. Токены IL
`MemberRef=0x0A`, `MethodDef=0x06`, `Field=0x04`, `TypeRef=0x01`, `string=0x70`
(старшие 8 бит токена = тип, младшие 24 = RID).

### 6.4. AES КЛЮЧ/IV НАЙДЕНЫ ✅ (2026-08-15, через ilspycmd + dnfile)
Декомпил `ilspycmd` раскрыл делегат-массивы. Ключ/IV строковой AES-VM собираются
методами (класс `aubDoAbSXgGwxT.AykNWbWxBoNpvcDU`):
- `sFiJMQXSvoLu()` → **KEY** (32B): читает FieldRVA `AsynchronousgetImpersonationLevel`,
  UTF-16LE строка, XOR по байту на чанк (0x3c, 0x25), два чанка + конкатенация.
- `SKxcWzQVNbkE()` → **IV** (16B): FieldRVA `LASTCALENDARClosedDelegateOnly`, та же схема.
- `ODCuBUBLJtbV(str,size)` = `Encoding.UTF8.GetBytes(str)`.

```
KEY = "hnYcSF4fEX2OR3iSJlF3tfw15geCn9uQ"   (32 байта UTF-8)
IV  = "2U0mqd3VL3bX7OBn"                    (16 байт UTF-8)
```
Проверка: AES-256-CBC этим ключом даёт валидный PKCS7-паддинг 120/120 строк
(случайный ключ — 0/120). Ключ ГАРАНТИРОВАННО верный.
Скрипты: `extract_keyiv.py`, `solve_strings.py`.

**Решено:** блоб по 0x2D0385 — таблица хэшей/токенов, не конфиг-строки.
Текстовые строки берутся из VM `awhuBmgthIGH(int index)` + массив `qWorhbBqOUAj`
(ресурс fMqF9GK0sigFT7melZ). Все 347 строк расшифрованы.

### 6.3. Кандидаты ключей (ОТВЕРГНУТЫ — ключ позже найден, см. §6.4)
- `0f7ae120062a248e2ab65243f26886a83d07998c07f347f4` (24 байта) — не ключ.
- `a62c86448442c0e007ae175000276707` (16 байт) — не IV.
- SHA256/HMAC-производные от них — не подошли.
- Вывод: ключ/IV собираются из VM-таблиц, готовым куском в бинаре их нет.
