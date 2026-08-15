# 12 — IL2CPP/Mono Hook Detection

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- IL2CPP old hook: `ocegetKeyInfoElement/Il2cppOldHook.cs`
- Mono native hook: `DateStartAsyncLocal/OldRustMonoNativeHook.cs`
- Assembly load: `UnsafeDeserializeNumTimesuff/OldRustAssemblyLoadDetector.cs`
- Строка: [752280840] `Il2cpp hook detected: {0} - {1} calls`
- Строка: [752280843] `Old Rust mono violation: Reason={0} Image={1} Path={2} LoadName={3} FileSize={4} MemorySize={5} Target={6}.{7}::{8} Source={9}`
- Строка: [752280842] `Old Rust assembly load violation: Reason=`
- Обфускация: Agile.NET

## Как работает

### Il2cppOldHook (для старых версий Rust на IL2CPP)
Хукает нативные функции Mono/IL2CPP runtime для перехвата загрузки чит-сборок:

| Хук | Назначение |
|-----|-----------|
| MonoImageOpenFromData | Перехват загрузки образов сборок из памяти |
| MonoAssemblyLoadFromFull | Перехват загрузки сборок из файла |
| MonoClassFromName | Перехват резолва классов по имени |
| MonoClassGetMethodFromName | Перехват поиска методов |
| MonoRuntimeInvoke | Перехват вызовов методов через рефлексию |

Методы:
- **HasInlineHookExports** — проверяет, есть ли inline-хуки в экспортах mono.dll
- **HasPassiveScannerExports** — проверяет наличие passive scanner-ов
- **InstallHook()** — устанавливает перехватчик

### OldRustMonoNativeHook
Аналогичная система для нативного Mono runtime. Детектирует:
- Подмену mono_image_open_from_data
- Загрузку неизвестных Image/Assembly
- Вызов методов из неизвестных сборок

Строка нарушения: `Old Rust mono violation: Reason={0} Image={1} Path={2} ...`

### OldRustAssemblyLoadDetector
- Подписывается на `AppDomain.AssemblyLoad` event
- При загрузке любой .NET сборки проверяет:
  - Является ли сборка `System.Reflection.RuntimeAssembly` [752280845]
  - Совпадает ли с белым списком
  - Если нет — генерирует `Old Rust assembly load violation`

## Как обойти

### Вариант A — Патч InstallHook() (рекомендуется)
В `Il2cppOldHook.InstallHook()` заменить тело на:
```
ret
```
Хуки не будут установлены, загрузка чит-сборок не будет перехвачена.

### Вариант B — Патч HasInlineHookExports / HasPassiveScannerExports
Заменить тела этих методов на:
```
ldc.i4.0    // false
ret
```
Сканер не обнаружит хуки.

### Вариант C — Патч OldRustAssemblyLoadDetector
Найти подписку на `AppDomain.AssemblyLoad` и NOP-ить `add` IL-инструкцию:
```
// Было:
ldsfld AppDomain.CurrentDomain
ldftn OnAssemblyLoad
newobj AssemblyLoadEventHandler
callvirt AppDomain::add_AssemblyLoad
// Заменить callvirt на nop-ы
```

### Вариант D — Подмена белого списка
Расширить белый список сборок, добавив имена чит-сборок в список разрешённых.

## Статус
- [ ] проверено / [ ] подтверждено
