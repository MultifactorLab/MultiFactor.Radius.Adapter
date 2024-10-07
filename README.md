[![Build Status](https://ci.appveyor.com/api/projects/status/github/MultifactorLab/MultiFactor.Radius.Adapter?svg=true)](https://ci.appveyor.com/project/MultifactorLab/multifactor-radius-adapter) [![License](https://img.shields.io/badge/license-view-orange)](https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md)

# MultiFactor.Radius.Adapter

_Also available in other languages: [Русский](README.ru.md)_

MultiFactor.Radius.Adapter is a RADIUS server for Windows. It allows to quickly add multifactor authentication through RADIUS protocol to your VPN, VDI, RDP and other resources.

The component is a part of <a href="https://multifactor.pro/" target="_blank">MultiFactor</a> 2FA hybrid solution.

* <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter" target="_blank">Source code</a>
* <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/releases" target="_blank">Build</a>

See documentation at <https://multifactor.pro/docs/radius-adapter/windows/> for additional guidance on integrating 2FA through RADIUS into your infrastracture.

Linux version of the component is available in our [multifactor-radius-adapter](https://github.com/MultifactorLab/multifactor-radius-adapter) repository.

## Table of Contents

* [Background](#background)
  * [Component Features](#component-features)
* [Prerequisites](#prerequisites)
* [Configuration](#configuration)
  * [General Parameters](#general-parameters)
  * [Active Directory Connection Parameters](#active-directory-connection-parameters)
  * [External RADIUS Server Connection](#external-radius-server-connection)
  * [Optional RADIUS Attributes](#optional-radius-attributes)
  * [Second factor verification parameters](#second-factor-verification-parameters)
* [Start Up](#start-up)
* [Logs](#logs)
* [Use Cases](#use-cases)
* [License](#license)

## Background

Remote Authentication Dial-In User Service (RADIUS) &mdash; is a networking protocol primarily used for remote user authentication.

The protocol has been around for a long time and is supported by major network devices and services vendors.

### Component Features

Key features:

1. Receive authentication requests through the RADIUS protocol;
2. Verify the first authentication factor &mdash; user login and password in Active Directory (AD) or Network Policy Server (NPS);
3. Verify the second authentication factor on the user's secondary device (usually, mobile phone).

Additional features:

* Inline enrollment within VPN/VDI client;
* Conditional access based on the user's group membership in Active Directory;
* Activate second factor selectively based on the user's group membership in Active Directory;
* Use user's phone number from Active Directory profile for one-time SMS passcodes;
* Configure RADIUS response attributes based on user's Active Directory group membership;
* Proxy Network Policy Server requests and responses;
* Send logs to Syslog server or SIEM.

## Prerequisites

* Component is installed on Windows Server starting from 2012 R2;
* Minimum server requirements: 2 CPUs, 4 GB RAM, 40 GB HDD (to run the OS and adapter for 100 simultaneous connections &mdash; about 1500 users);
* UDP 1812 port on the server should accept inbound requests from Radius clients;
* The server with the component installed needs access to ```api.multifactor.ru``` via TCP port 443 (TLS) or via HTTP proxy;
* To interact with Active Directory, the component needs access to the AD domain server on TCP 389 port;
* To interact with Network Policy Server (NPS), the component needs access to NPS on the UDP 1812 port.

## Configuration

The component's parameters are stored in ```MultiFactor.Radius.Adapter.exe.config``` file in XML format.

### General Parameters

```xml
<appSettings>
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
  <!--Timeout for requests in the Multifactor API, the minimum value is 65 seconds-->
  <add key="multifactor-api-timeout" value="00:01:05"/>

  <!-- Logging level: 'Debug', 'Info', 'Warn', 'Error' -->
  <add key="logging-level" value="Debug"/>

  <!-- [Optional] Enable/disable nested group checking in active directory -->
  <add key="load-active-directory-nested-groups" value="false"/>

  <!-- [Optional] Base dn(s) separated by ';' for user nested groups checking.
  Specify the containers in which to search for nested groups. -->
  <add key="nested-groups-base-dn" value="CN=Users,DC=domain,DC=your;OU=Admins,DC=domain,DC=your"/>
</appSettings>
```

### Active Directory Connection Parameters

To check the first factor in the domain, the following parameters apply:

```xml
<appSettings>
  <!--Domain-->
  <add key="active-directory-domain" value="domain.local"/>

  <!-- Give access to users from specified group only (not checked if setting is removed)-->
  <add key="active-directory-group" value="VPN Users"/>
  <!--Require the second factor for users from a specified group only (second factor is required for users if the setting is removed)-->
  <add key="active-directory-2fa-group" value="2FA Users"/>
  <!-- Use your users' phone numbers listed in Active Directory to send one-time SMS codes (not used if settings are removed)-->
  <!--add key="use-active-directory-user-phone" value="true"/-->
  <!--add key="use-active-directory-mobile-user-phone" value="true"/-->
</appSettings>
```

When the ```use-active-directory-user-phone``` option is enabled, the component will use the phone recorded in the General tab. The format of the phone can be anything.

<img src="https://multifactor.pro/img/radius-adapter/ra-ad-phone-source.png" width="300">

When the ```use-active-directory-mobile-user-phone``` option is enabled, the component will use the phone recorded in the Telephones tab in the Mobile field. The format of the phone can also be any format.

<img src="https://multifactor.pro/img/radius-adapter/ra-ad-mobile-phone-source.png" width="300">

### External RADIUS Server Connection

To check the first factor in another RADIUS server, eg. in Network Policy Server, the following parameters apply:

```xml
<appSettings>
  <!--Address (UDP) from which the adapter will connect to the server -->
  <add key="adapter-client-endpoint" value="192.168.0.1"/>
  <!-- Server address and port (UDP) -->
  <add key="nps-server-endpoint" value="192.168.0.10:1812"/>
</appSettings>
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

### Second factor verification parameters

The following parameters will help you set up access to the MULTIFACTOR API when checking the second factor:

```xml
<appSettings>
  <!-- Use the specified attribute as the user identity when checking the second factor-->
  <add key="use-attribute-as-identity" value="mail"/>
  <!-- Skip repeated authentications without requesting the second factor for 1 hour, 20 minutes, 10 seconds (caching is disabled if you remove the setting) -->
  <add key="authentication-cache-lifetime" value="01:20:10" />
  <!-- If the API is unavailable, skip the MULTIFACTOR without checking (by default), or deny access (false) -->
  <add key="bypass-second-factor-when-api-unreachable" value="true"/>
  <!-- Automatically assign MULTIFACTOR group membership to registering users -->
  <add key="sign-up-groups" value="group1;Group name 2"/>
</appSettings>
```

### Logging

There are such options to customize logging:

```xml
<appSettings>
  <!--Allows you to customize the template of logs which get into the console -->
  <add key="console-log-output-template" value="outputTemplate"/>
  <!--Allows you to customize the logs template which get into the file -->
  <add key="file-log-output-template" value="outputTemplate"/>
  <!--Allows you to customize the logs template which get into the remote syslog server -->
  <add key="syslog-output-template" value="outputTemplate"/>
</appSettings>
```

As ```outputTemplate``` also acts text template which shows the logging system how the message should be formatted. For example

 ```sh
[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}
[{Timestamp:HH:mm:ss} {Level:u3}] {CorrelationId} {Message:lj}{NewLine}{Exception} 
```

For more information [see this page.](https://github.com/serilog/serilog/wiki/Formatting-Output)

Moreover, logging can be provided in json (for console and file only):

```xml
<appSettings>
  <add key="logging-format" value="json"/>
</appSettings>
```
> Keep in mind that `console-log-output-template` and `file-log-output-template` settings are not applicable for the JSON log format.

Sometimes there may be a delay in writing logs to a file, or a situation where logs are written to a file only after the process has completed. For these cases, there is a setting with which you can control the frequency of flushing logs to a file:
```xml
<appSettings>
  <!-- Write logs at least once every 10 seconds -->
  <add key="log-file-flush-interval" value="00:00:10"/>
</appSettings>
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

* Two-factor authentication for VPN devices [Cisco](https://multifactor.pro/docs/vpn/cisco-anyconnect-vpn-2fa/), [Fortigate](https://multifactor.pro/docs/vpn/fortigate-forticlient-vpn-2fa/), [CheckPoint](https://multifactor.pro/docs/vpn/checkpoint-remote-access-vpn-2fa/), Mikrotik, Huawei and others;
* Two-factor authentication for [Windows VPN with Routing and Remote Access Service (RRAS)](https://multifactor.pro/docs/windows-2fa-rras-vpn/);
* Two-factor authentication for [Microsoft Remote Desktop Gateway](https://multifactor.pro/docs/windows-2fa-remote-desktop-gateway/) ;
* Two-factor authentication for [VMware Horizon](https://multifactor.pro/docs/vmware-horizon-2fa/);
* [Citrix Gateway](https://multifactor.pro/docs/citrix-radius-2fa/) two-factor authentication;
* Apache Guacamole two-factor authentication;
* Two-factor authentication for Wi-Fi hotspots;

and many more...

## License

Please note, the <a href="https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md" target="_blank">license</a> does not entitle you to modify the source code of the Component or create derivative products based on it. The source code is provided as-is for evaluation purposes.
