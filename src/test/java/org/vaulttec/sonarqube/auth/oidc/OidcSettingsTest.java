/*
 * OpenID Connect Authentication for SonarQube
 * Copyright (c) 2017 Torsten Juergeleit
 * mailto:torsten AT vaulttec DOT org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.vaulttec.sonarqube.auth.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.vaulttec.sonarqube.auth.oidc.OidcSettings.LOGIN_STRATEGY_PROVIDER_ID;

import org.junit.Test;
import org.sonar.api.config.PropertyDefinitions;
import org.sonar.api.config.Settings;

public class OidcSettingsTest {

  Settings settings = new Settings(new PropertyDefinitions(OidcSettings.definitions()));

  OidcSettings underTest = new OidcSettings(settings);

  @Test
  public void is_enabled() {
    settings.setProperty("sonar.auth.oidc.providerConfiguration", getProviderConfiguration());
    settings.setProperty("sonar.auth.oidc.clientId.secured", "id");

    settings.setProperty("sonar.auth.oidc.enabled", true);
    assertThat(underTest.isEnabled()).isTrue();

    settings.setProperty("sonar.auth.oidc.enabled", false);
    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_enabled_always_return_false_when_provider_configuration_is_null() {
    settings.setProperty("sonar.auth.oidc.providerConfiguration", (String) null);
    settings.setProperty("sonar.auth.oidc.clientId.secured", "id");
    settings.setProperty("sonar.auth.oidc.enabled", true);

    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_enabled_always_return_false_when_client_id_is_null() {
    settings.setProperty("sonar.auth.oidc.providerConfiguration", getProviderConfiguration());
    settings.setProperty("sonar.auth.oidc.clientId.secured", (String) null);
    settings.setProperty("sonar.auth.oidc.enabled", true);

    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void default_login_strategy_is_preferred_username() {
    assertThat(underTest.loginStrategy()).isEqualTo(OidcSettings.LOGIN_STRATEGY_PREFERRED_USERNAME);
  }

  @Test
  public void configure_provider_configurationi() throws Exception {
    final String configuredConfiguration = getProviderConfiguration();

    settings.setProperty("sonar.auth.oidc.providerConfiguration", configuredConfiguration);

    assertThat(underTest.providerConfiguration()).isEqualTo(configuredConfiguration);
  }

  @Test
  public void return_client_id() {
    settings.setProperty("sonar.auth.oidc.clientId.secured", "id");
    assertThat(underTest.clientId()).isEqualTo("id");
  }

  @Test
  public void return_client_secret() {
    settings.setProperty("sonar.auth.oidc.clientSecret.secured", "secret");
    assertThat(underTest.clientSecret()).isEqualTo("secret");
  }

  @Test
  public void return_login_strategy() {
    settings.setProperty("sonar.auth.oidc.loginStrategy", LOGIN_STRATEGY_PROVIDER_ID);
    assertThat(underTest.loginStrategy()).isEqualTo(LOGIN_STRATEGY_PROVIDER_ID);
  }

  @Test
  public void allow_users_to_sign_up() {
    settings.setProperty("sonar.auth.oidc.allowUsersToSignUp", "true");
    assertThat(underTest.allowUsersToSignUp()).isTrue();

    settings.setProperty("sonar.auth.oidc.allowUsersToSignUp", "false");
    assertThat(underTest.allowUsersToSignUp()).isFalse();
  }

  @Test
  public void group_sync() {
    settings.setProperty("sonar.auth.oidc.groupsSync", "true");
    assertThat(underTest.syncGroups()).isTrue();

    settings.setProperty("sonar.auth.oidc.groupsSync", "false");
    assertThat(underTest.syncGroups()).isFalse();
  }

  @Test
  public void definitions() {
    assertThat(OidcSettings.definitions()).hasSize(7);
  }

  private String getProviderConfiguration() {
    final String configuredConfiguration = "{\"issuer\":\"http://localhost/auth/realms/sso\","
        + "\"authorization_endpoint\":\"http://localhost/auth/realms/sso/protocol/openid-connect/auth\"}";
    return configuredConfiguration;
  }

}
