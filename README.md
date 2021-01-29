[![Build Status](https://ci.appveyor.com/api/projects/status/github/MultifactorLab/MultiFactor.Radius.Adapter?svg=true)](https://ci.appveyor.com/project/MultifactorLab/multifactor-radius-adapter) [![License](https://img.shields.io/badge/license-view-orange)](https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md)

# MultiFactor.Radius.Adapter

_Also available in other languages: [Русский](README.ru.md)_

MultiFactor.Radius.Adapter is a RADIUS server for Windows. It allows to quickly add multifactor authentication through RADIUS protocol to your VPN, VDI, RDP and other resources.

The component is a part of <a href="https://multifactor.pro/" target="_blank">MultiFactor</a> 2FA hybrid solution.

* <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter" target="_blank">Source code</a>
* <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/releases" target="_blank">Build</a>

See documentation at https://multifactor.pro/docs/radius-adapter/windows/ for additional guidance on integrating 2FA through RADIUS into your infrastracture.

Linux version of the component is available in our [multifactor-radius-adapter](https://github.com/MultifactorLab/multifactor-radius-adapter) repository.

## Table of Contents

- [Background](#background)
	- [Component Features](#component-features)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
  - [General Parameters](#general-parameters)
  - [Active Directory Connection Parameters](#active-directory-connection-parameters)
  - [External RADIUS Server Connection](#external-radius-server-connection)
  - [Optional RADIUS Attributes](#optional-radius-attributes)
- [Start Up](#start-up)
- [Logs](#logs)
- [Use Cases](#use-cases)
- [License](#license)

## Background

Remote Authentication Dial-In User Service (RADIUS) &mdash; is a networking protocol primarily used for remote user authentication.

The protocol has been around for a long time and is supported by major network devices and services vendors.

### Component Features

Key features:

1. Receive authentication requests through the RADIUS protocol;
2. Verify the first authentication factor &mdash; user login and password in Active Directory (AD) or Network Policy Server (NPS);
3. Verify the second authentication factor on the user's secondary device (usually, mobile phone).

Additional features:

- Set up access based on the user's group membership in Active Directory;
- Activate second factor selectively based on the user's group membership in Active Directory;
- Use user's phone number from Active Directory profile for one-time SMS passcodes;
- Configure RADIUS response attributes based on user's Active Directory group membership;
- Proxy Network Policy Server requests and responses.

## Prerequisites

- Component is installed on Windows Server starting from 2012 R2;
- Minimum server requirements: 2 CPUs, 4 GB RAM, 40 GB HDD (to run the OS and adapter for 100 simultaneous connections &mdash; about 1500 users);
- UDP 1812 port on the server should accept inbound requests from Radius clients;
- The server with the component installed needs access to ```api.multifactor.ru``` via TCP port 443 (TLS) or via HTTP proxy;
- To interact with Active Directory, the component needs access to the AD domain server on TCP 389 port;
- To interact with Network Policy Server (NPS), the component needs access to NPS on the UDP 1812 port.

## Configuration

The component's parameters are stored in ```MultiFactor.Radius.Adapter.exe.config``` file in XML format.

### General Parameters

```xml
<!-- The address and port (UDP) on which the adapter will receive authentication requests from clients -->
<!-- If you specify 0.0.0.0, then the adapter will listen on all network interfaces -->
<add key="adapter-server-endpoint" value="192.168.0.1:1812"/>

<!-- Shared secret to authenticate RADIUS clients -->
<add key="radius-shared-secret" value=""/>

<!-- How to check the first factor: Active Directory, RADIUS or None (do not check) -->
<add key="first-factor-authentication-source" value="ActiveDirectory"/>

<!-- Multifactor API address -->
<add key="multifactor-api-url" value="https://api.multifactor.ru"/>
<!-- NAS-Identifier parameter to connect to the Multifactor API (found in user profile) -->
<add key="multifactor-nas-identifier" value=""/>
<!-- Shared Secret parameter for connection to the Multifactor API (found in user profile) -->
<add key="multifactor-shared-secret" value=""/>

<!-- Access to the Multifactor API via HTTP proxy (optional)-->
<!--add key="multifactor-api-proxy" value="http://proxy:3128"/-->

<!-- Logging level: 'Debug', 'Info', 'Warn', 'Error' -->
<add key="logging-level" value="Debug"/>
```

### Active Directory Connection Parameters

To check the first factor in the domain, the following parameters apply:
```xml
<!--Domain-->
<add key="active-directory-domain" value="domain.local"/>

<!-- Give access to users from specified group only (not checked if setting is removed)-->
<add key="active-directory-group" value="VPN Users"/>
<!--Require the second factor for users from a specified group only (second factor is required for users if the setting is removed)-->
<add key="active-directory-2fa-group" value="2FA Users"/>
<!-- Use your users' phone numbers listed in Active Directory to send one-time SMS codes (not used if settings are removed)-->
<!--add key="use-active-directory-user-phone" value="true"/-->
<!--add key="use-active-directory-mobile-user-phone" value="true"/-->
```
When the ```use-active-directory-user-phone``` option is enabled, the component will use the phone recorded in the General tab. The format of the phone can be anything.

<img src="https://multifactor.pro/img/radius-adapter/ra-ad-phone-source.png" width="300">

When the ```use-active-directory-mobile-user-phone``` option is enabled, the component will use the phone recorded in the Telephones tab in the Mobile field. The format of the phone can also be any format.

<img src="https://multifactor.pro/img/radius-adapter/ra-ad-mobile-phone-source.png" width="300">

### External RADIUS Server Connection

To check the first factor in another RADIUS server, eg. in Network Policy Server, the following parameters apply:
```xml
<!--Address (UDP) from which the adapter will connect to the server -->
<add key="adapter-client-endpoint" value="192.168.0.1"/>
<!-- Server address and port (UDP) -->
<add key="nps-server-endpoint" value="192.168.0.10:1812"/>
```
### Optional RADIUS Attributes

You can specify attributes the component will pass further upon successful authentication, including verification that the user is a member of a security group.
```xml
<RadiusReply>
    <Attributes>
        <!--This is an example, you can use any attributes-->
        <add name="Class" value="Super" />
        <add name="Fortinet-Group-Name" value="Users" when="UserGroup=VPN Users"/>
        <add name="Fortinet-Group-Name" value="Admins" when="UserGroup=VPN Admins"/>
    </Attributes>
</RadiusReply>
```

## Start-Up

The component can run in console mode or as a Windows service. To run in console mode, just run the application.

To install it as a Windows Service, start it with the ```/i``` key as the Administrator
```shell
MultiFactor.Radius.Adapter.exe /i
```
The component is installed in auto-startup mode by default on behalf of ```Network Service```.

To remove the Windows Service run with the ```/u``` key as Administrator
```shell
MultiFactor.Radius.Adapter.exe /u
```

## Logs

Component's logs are located in the ```Logs``` folder. If they are not there, make sure that the folder is writable by the ```Network Service``` user.

## Use Cases

Use Radius Adapter Component to implement 2FA in one of the following scenarios:

- Two-factor authentication for VPN devices [Cisco](https://multifactor.pro/docs/vpn/cisco-anyconnect-vpn-2fa/), [Fortigate](https://multifactor.pro/docs/vpn/fortigate-forticlient-vpn-2fa/), [CheckPoint](https://multifactor.pro/docs/vpn/checkpoint-remote-access-vpn-2fa/), Mikrotik, Huawei and others;
- Two-factor authentication for [Windows VPN with Routing and Remote Access Service (RRAS)](https://multifactor.pro/docs/windows-2fa-rras-vpn/);
- Two-factor authentication for [Microsoft Remote Desktop Gateway](https://multifactor.pro/docs/windows-2fa-remote-desktop-gateway/) ;
- Two factor authentication for [VMware Horizon](/docs/vmware-horizon-2fa/);
- [Citrix Gateway](https://multifactor.pro/docs/citrix-radius-2fa/) two-factor authentication;
- Apache Guacamole two-factor authentication;
- Two-factor authentication for Wi-Fi hotspots;

and many more...

## License

Please note, the <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md" target="_blank">license</a> does not entitle you to modify the source code of the Component or create derivative products based on it. The source code is provided as-is for evaluation purposes.