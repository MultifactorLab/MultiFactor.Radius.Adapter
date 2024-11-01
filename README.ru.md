[![Статус сборки](https://ci.appveyor.com/api/projects/status/github/MultifactorLab/MultiFactor.Radius.Adapter?svg=true)](https://ci.appveyor.com/project/MultifactorLab/multifactor-radius-adapter) [![Лицензия](https://img.shields.io/badge/license-view-orange)](https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.ru.md)

# MultiFactor.Radius.Adapter

_Also available in other languages: [English](README.md)_

MultiFactor Radius Adapter &mdash; программный компонент, RADIUS сервер для Windows. Позволяет быстро подключить мультифакторную аутентификацию по протоколу RADIUS к вашим VPN, VDI, RDP и другим ресурсам.

Компонент является частью гибридного 2FA решения сервиса <a href="https://multifactor.ru/" target="_blank">MultiFactor</a>.

* <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter" target="_blank">Исходный код</a>
* <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/releases" target="_blank">Сборка</a>

Дополнительные инструкции по интеграции 2FA через RADIUS в вашу инфраструктуру см. в документации по адресу https://multifactor.pro/docs/radius-adapter/windows/.

Linux-версия компонента также доступна в [linux-репозитории](https://github.com/MultifactorLab/multifactor-radius-adapter).

## Содержание

* [Общие сведения](#общие-сведения)
  * [Функции компонента](#функции-компонента)
* [Требования для установки компонента](#требования-для-установки-компонента)
* [Конфигурация](#конфигурация)
  * [Общие параметры](#общие-параметры)
  * [Параметры подключения к Active Directory](#параметры-подключения-к-active-directory)
  * [Параметры подключения к внешнему RADIUS серверу](#параметры-подключения-к-внешнему-radius-серверу)
  * [Дополнительные RADIUS атрибуты](#дополнительные-radius-атрибуты)
  * [Параметры проверки второго фактора](#параметры-проверки-второго-фактора)
* [Запуск компонента](#запуск-компонента)
* [Журналы](#журналы)
* [Сценарии использования](#сценарии-использования)
* [Лицензия](#лицензия)

## Общие сведения

Что такое RADIUS?

Remote Authentication Dial-In User Service (RADIUS) &mdash; сетевой протокол для удаленной аутентификации пользователей в единой базе данных доступа.

Протокол создан достаточно давно и поэтому поддерживается множеством сетевых утройств и сервисов.

### Функции компонента

Ключевые функции:

1. Прием запросов на аутентификацию по протоколу RADIUS;
2. Проверка первого фактора аутентификации &mdash; логина и пароля пользователя в Active Directory или Network Policy Server;
3. Проверка второго фактора аутентификации на дополнительном устройстве пользователя (обычно, телефон).

Дополнительные возможности:

* регистрация второго фактора непосредственно в VPN/VDI клиенте при первом подключении;
* настройка доступа на основе принадлежности пользователя к группе в Active Directory;
* избирательное включение второго фактора на основе принадлежности пользователя к группе в Active Directory;
* использование телефона пользователя из профиля Active Directory для отправки одноразового кода через СМС;
* настройка атрибутов ответа RADIUS на основе принадлежности пользователя к группе Active Directory;
* проксирование запросов и ответов Network Policy Server;
* запись журналов в Syslog сервер или SIEM систему.

## Требования для установки компонента

* Компонент устанавливается на любой Windows сервер начиная с версии 2012 R2;
* Минимальные требования для сервера: 2 CPU, 4 GB RAM, 40 GB HDD (обеспечивают работу ОС и адаптера для 100 одновременных подключений &mdash; примерно 1500 пользователей);
* На сервере должен быть открыт порт 1812 (UDP) для приема запросов от Radius клиентов;
* Серверу с установленным компонентом необходим доступ к хосту api.multifactor.ru по TCP порту 443 (TLS) напрямую или через HTTP proxy;
* Для взаимодействия с Active Directory, компоненту нужен доступ к серверу домена по TCP порту 389;
* Для взаимодействия с Network Policy Server, компоненту нужен доступ к NPS по UDP порту 1812.

## Конфигурация

Параметры работы компонента хранятся в файле ```MultiFactor.Radius.Adapter.exe.config``` в формате XML.

### Общие параметры

```xml
<appSettings>
  <!-- Адрес и порт (UDP) по которому адаптер будет принимать запросы на аутентификацию от клиентов -->
  <!-- Если указать адрес 0.0.0.0, то адаптер будет слушать все сетевые интерфейсы-->
  <add key="adapter-server-endpoint" value="192.168.0.1:1812"/>

  <!-- Shared secret для аутентификации RADIUS клиентов -->
  <add key="radius-shared-secret" value=""/>

  <!--Где проверять первый фактор: ActiveDirectory или RADIUS или None (не проверять) -->
  <add key="first-factor-authentication-source" value="ActiveDirectory"/>

  <!--Адрес API Мультифактора -->
  <add key="multifactor-api-url" value="https://api.multifactor.ru"/>
  <!--Таймаут запросов в API Мультифактора, минимальное значение 65 секунд -->
  <add key="multifactor-api-timeout" value="00:01:05"/>
  <!-- Параметр NAS-Identifier для подключения к API Мультифактора - из личного кабинета -->
  <add key="multifactor-nas-identifier" value=""/>
  <!-- Параметр Shared Secret для подключения к API Мультифактора - из личного кабинета -->
  <add key="multifactor-shared-secret" value=""/>

  <!--Доступ к API Мультифактора через HTTP прокси (опционально)-->
  <!--add key="multifactor-api-proxy" value="http://proxy:3128"/-->
  
  <!-- [Опционально] Таймаут для ldap bind запроса. Значение по умолчанию 30 секунд -->
  <add key="ldap-bind-timeout" value="00:00:30"/>
  
  <!-- Уровень логирования: 'Debug', 'Info', 'Warn', 'Error' -->
  <add key="logging-level" value="Debug"/>

  <!-- [Опционально] Включить/отключить проверку вложенных групп в Active Directory -->
  <add key="load-active-directory-nested-groups" value="false"/>

  <!-- [Опционально] Базовые dn, разделенные ';' для проверки вложенных групп пользователя.
  Укажите контейнеры, в которых следует искать вложенные группы. -->
  <add key="nested-groups-base-dn" value="CN=Users,DC=domain,DC=your;OU=Admins,DC=domain,DC=your"/>
</appSettings>
```

### Параметры подключения к Active Directory

Для проверки первого фактора в домене применимы следующие параметры:

```xml
<appSettings>
  <!--Домен-->
  <add key="active-directory-domain" value="domain.local"/>

  <!--Разрешать доступ только пользователям из указанной группы (не проверяется, если удалить настройку)-->
  <add key="active-directory-group" value="VPN Users"/>
  <!--Запрашивать второй фактор только у пользователей из указанной группы (второй фактор требуется всем, если удалить настройку)-->
  <add key="active-directory-2fa-group" value="2FA Users"/>
  <!--Использовать номер телефона из Active Directory для отправки одноразового кода в СМС (не используется, если удалить настройку)-->
  <!--add key="use-active-directory-user-phone" value="true"/-->
  <!--add key="use-active-directory-mobile-user-phone" value="true"/-->
</appSettings>
```

При включении параметра ```use-active-directory-user-phone``` компонент будет использовать телефон, записанный на вкладке General. Формат телефона может быть любым.

<img src="https://multifactor.ru/img/radius-adapter/ra-ad-phone-source.png" width="300" alt="AD phone">

При включении параметра ```use-active-directory-mobile-user-phone``` компонент будет использовать телефон, записанный на вкладке Telephones в поле Mobile. Формат телефона также может быть любым.

<img src="https://multifactor.ru/img/radius-adapter/ra-ad-mobile-phone-source.png" width="300" alt="AD mobile phone">

### Параметры подключения к внешнему RADIUS серверу

Для проверки первого фактора в RADIUS, например, в Network Policy Server применимы следующие параметры:

```xml
<appSettings>
  <!--Адрес (UDP) с которого адаптер будет подключаться к серверу -->
  <add key="adapter-client-endpoint" value="192.168.0.1"/>
  <!--Адрес и порт (UDP) сервера -->
  <add key="nps-server-endpoint" value="192.168.0.10:1812"/>
</appSettings>
```

### Дополнительные RADIUS атрибуты

Можно указать, какие атрибуты будет передавать компонент при успешной аутентификации, в том числе с проверкой вхождения пользователя в группу безопасности

```xml
<RadiusReply>
    <Attributes>
        <!--Это пример, можно использовать любые атрибуты-->
        <add name="Class" value="Super" />
        <add name="Fortinet-Group-Name" value="Users" when="UserGroup=VPN Users"/>
        <add name="Fortinet-Group-Name" value="Admins" when="UserGroup=VPN Admins"/>
    </Attributes>
</RadiusReply>
```

### Параметры проверки второго фактора

Следующие параметры помогут настроить обращение в API МУЛЬТИФАКТОР при проверке второго фактора:

```xml
<appSettings>
  <!-- Использовать указанный аттрибут в качестве идентификатора пользователя при проверке второго фактора-->
  <add key="use-attribute-as-identity" value="mail"/>
  <!-- Пропускать повторные аутентификации без запроса второго фактора в течение 1 часа 20 минут 10 секунд (кэширование отключено, если удалить настройку) -->
  <add key="authentication-cache-lifetime" value="01:20:10" />
  <!-- В случае недоступности API МУЛЬТИФАКТОР пропускать без проверки (по умолчанию), либо запрещать доступ (false) -->
  <add key="bypass-second-factor-when-api-unreachable" value="true"/>
  <!-- Автоматически присваивать членство в группах МУЛЬТИФАКТОР регистрирующимся пользователям -->
  <add key="sign-up-groups" value="group1;Название группы 2"/>
</appSettings>
```

### Журналирование

Существуют следующие параметры для настройки журналирования:

```xml
<appSettings>
  <!--Позволяет настроить шаблон логов, которые попадают в системный журнал -->
  <add key="console-log-output-template" value="outputTemplate"/>
  <!--Позволяет настроить шаблон логов, которые попадают в файл -->
  <add key="file-log-output-template" value="outputTemplate"/>
  <!--Позволяет настроить шаблон логов, которые отправляются в удаленный syslog-сервер -->
  <add key="syslog-output-template" value="outputTemplate"/>
</appSettings>
```

В качестве ```outputTemplate``` выступает текстовый шаблон, который показывает системе ведения логов, как следует отформатировать сообщение. Например:

 ```sh
[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}
[{Timestamp:HH:mm:ss} {Level:u3}] {CorrelationId} {Message:lj}{NewLine}{Exception} 
```

Подробнее про шаблоны можно прочитать [по ссылке.](https://github.com/serilog/serilog/wiki/Formatting-Output)

Также журналирование может вестись в формате json:

```xml
<appSettings>
  <add key="logging-format" value="format"/>
</appSettings>
```
> Для этого формата не применим текстовый шаблон.

Иногда может возникать задержка при записи логов в файл, либо ситуация, когда логи появляются в файле только после завершения процесса. Для этих случаев предусмотрена настройка, через которую можно управлять частотой сбросов логов в файл:  
```xml
<appSettings>
  <!-- Записывать не реже одного раза в 10 секунд -->
  <add key="log-file-flush-interval" value="00:00:10"/>
</appSettings>
```

## Запуск компонента

Компонент может работать в консольном режиме или в качестве службы Windows. Для запуска в консольном режиме достаточно запустить приложение.

Для установки в качестве Windows Service выполните команду с ключом ```/i``` от имени Администратора

```shell
MultiFactor.Radius.Adapter.exe /i
```

Компонент устанавливается в режиме автоматического запуска от имени ```Network Service```.

Для удаления Windows Service выполните команду с ключом ```/u``` от имени Администратора

```shell
MultiFactor.Radius.Adapter.exe /u
```

## Журналы

Журналы работы компонента находятся в папке ```Logs```. Если их нет, удостоверьтесь, что папка доступна для записи пользователю ```Network Service```.

## Сценарии использования

С помощью компонента можно реализовать следующие сценарии:

* Двухфакторная аутентификация для VPN устройств [Cisco](https://multifactor.ru/docs/vpn/cisco-anyconnect-vpn-2fa/), [Fortigate](https://multifactor.ru/docs/vpn/fortigate-forticlient-vpn-2fa/), [CheckPoint](https://multifactor.ru/docs/vpn/checkpoint-remote-access-vpn-2fa/), Mikrotik, Huawei и других;
* Двухфакторная аутентификация [Windows VPN со службой Routing and Remote Access Service (RRAS)](https://multifactor.ru/docs/windows-2fa-rras-vpn/);
* Двухфакторная аутентификация [Microsoft Remote Desktop Gateway](https://multifactor.ru/docs/windows-2fa-remote-desktop-gateway/);
* Двухфакторная аутентификация [VMware Horizon](https://multifactor.ru/docs/vmware-horizon-2fa/);
* Двухфакторная аутентификация [Citrix Gateway](https://multifactor.ru/docs/citrix-radius-2fa/);
* Двухфакторная аутентификация Apache Guacamole;
* Двухфакторная аутентификация Wi-Fi точек доступа;

и многие другие...

## Лицензия

Обратите внимание на <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.ru.md" target="_blank">лицензию</a>. Она не дает вам право вносить изменения в исходный код Компонента и создавать производные продукты на его основе. Исходный код предоставляется в ознакомительных целях.
