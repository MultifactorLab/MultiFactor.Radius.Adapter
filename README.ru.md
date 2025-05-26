
[![Статус сборки](https://ci.appveyor.com/api/projects/status/github/MultifactorLab/MultiFactor.Radius.Adapter?svg=true)](https://ci.appveyor.com/project/MultifactorLab/multifactor-radius-adapter) [![Лицензия](https://img.shields.io/badge/license-view-orange)](https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.ru.md)

# MultiFactor.Radius.Adapter

_Also available in other languages: [English](README.md)_

## Что такое Multifactor radius adapter?
MultiFactor Radius Adapter &mdash; программный компонент, RADIUS сервер для Windows. Позволяет быстро подключить мультифакторную аутентификацию по протоколу RADIUS к вашим VPN, VDI, RDP и другим ресурсам.

Компонент является частью гибридного 2FA решения сервиса <a href="https://multifactor.ru/" target="_blank">MultiFactor</a>.

* <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter" target="_blank">Исходный код</a>
* <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/releases" target="_blank">Релизы</a>

## Содержание
* [Что такое Multifactor radius adapter?](#что-такое-multifactor-radius-adapter?)
* [Функции компонента](#функции-компонента)
* [Сценарии использования](#сценарии-использования)
* [Установка и конфигурация](#установка-и-конфигурация)
* [Лицензия](#лицензия)


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

## Установка и конфигурация
Информацию о настройке, запуске и дополнительные рекомендации смотрите в [документации](https://multifactor.ru/docs/radius-adapter/windows/).

## Лицензия

Обратите внимание на <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.ru.md" target="_blank">лицензию</a>. Она не дает вам право вносить изменения в исходный код Компонента и создавать производные продукты на его основе. Исходный код предоставляется в ознакомительных целях.