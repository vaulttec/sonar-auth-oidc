# OpenID Connect (OIDC) Plugin for SonarQube
[![Build Status](https://api.travis-ci.org/vaulttec/sonar-auth-oidc.svg)](https://travis-ci.org/vaulttec/sonar-auth-oidc) [![Quality Gate](https://sonarcloud.io/api/badges/gate?key=org.vaulttec.sonarqube.auth.oidc:sonar-auth-oidc-plugin)](https://sonarcloud.io/dashboard?id=org.vaulttec.sonarqube.auth.oidc%3Asonar-auth-oidc-plugin) [![Release](https://img.shields.io/github/release/vaulttec/sonar-auth-oidc.svg)](https://github.com/vaulttec/sonar-auth-oidc/releases/latest)

## Description

This plugin enables users to automatically be sign up and authenticated on a SonarQube server via an [OpenID Connect](http://openid.net/connect/) identity provider like [Keycloak](http://www.keycloak.org). Optionally the groups a user is associated in SonarQube can be synchronized with the provider (via the userinfo claim `groups` retrieved from the ID token).

## Prerequisites

### Server Base URL

`Server base URL` property must be set either by setting the
URL from SonarQube administration page (General -\> Server base URL) or
through setting `sonar.core.serverBaseURL` key value in the `sonar.properties`
file.

**In this URL no trailing slash is allowed!** Otherwise the redirects from the identity provider back to the SonarQube server are not created correctly.

### Network Proxy

If a [network proxy](https://docs.oracle.com/javase/8/docs/api/java/net/doc-files/net-properties.html#Proxies) is used with SonarQube (via `http[s].proxy[Host|Port]` properties in the `sonar.properties`) and the host name of the identity provider is not resolvable by this proxy then the IdP's host name must be excluded from being resolved by the proxy. This is done by defining the property `http.nonProxyHosts` in the `sonar.properties`.

**Otherwise the plugin won't be able to send the token request to the IdP.**

## Installation

1. Download the latest plugin from the [GitHub Releases](https://github.com/vaulttec/sonar-auth-oidc/releases) and put it into the `SONARQUBE_HOME/extensions/plugins/` directory
1. Restart the SonarQube server

## Configuration

- In OpenID Connect identity provider:
  - Create a client with access type 'public' or 'confidential' (in the latter case the corresponding client secret must be set in the plugin configuration) and valid redirect URI(s) for the SonarQube server
    ![Keycloak Client Configuration](docs/images/keycloak-client-config.png)

  - For synchronizing SonarQube groups create a mapper which adds group names to the userinfo claim `groups` in the ID token
    ![Keycloak Mapper Configuration](docs/images/keycloak-mapper-config.png)

  - Retrieve the provider's endpoint configuration as JSON text (needed for plugin configuration)
    ![Keycloak Client Configuration](docs/images/keycloak-endpoint-config.png)

- In SonarQube administration (General-\> Security -\> OpenID Connect):
  - Configure the plugin for the OpenID Connect client (a client secret is only required for clients with access type 'confidential')
    ![SonarQube Plugin Configuration](docs/images/plugin-config.png)

## Tested with

* SonarQube 6.7.1
* Keycloak 3.4.2.Final
