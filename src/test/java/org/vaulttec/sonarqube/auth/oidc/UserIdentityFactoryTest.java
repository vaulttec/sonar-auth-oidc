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

import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.PropertyDefinitions;
import org.sonar.api.config.Settings;
import org.sonar.api.server.authentication.UserIdentity;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

public class UserIdentityFactoryTest {

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  Settings settings = new Settings(new PropertyDefinitions(OidcSettings.definitions()));
  UserIdentityFactory underTest = new UserIdentityFactory(new OidcSettings(settings));

  @Test
  public void create_for_provider_strategy() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty(OidcSettings.LOGIN_STRATEGY, OidcSettings.LOGIN_STRATEGY_PROVIDER_ID);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getLogin()).isEqualTo("8f63a486-6699-4f25-beef-118dd240bef8");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void create_for_unique_login_strategy() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty(OidcSettings.LOGIN_STRATEGY, OidcSettings.LOGIN_STRATEGY_UNIQUE);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getLogin()).isEqualTo("8f63a486-6699-4f25-beef-118dd240bef8@oidc");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void create_for_preferred_username_login_strategy() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty(OidcSettings.LOGIN_STRATEGY, OidcSettings.LOGIN_STRATEGY_PREFERRED_USERNAME);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getLogin()).isEqualTo("jdoo");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void no_email() {
    UserInfo userInfo = newUserInfo();
    userInfo.setEmailAddress(null);
    settings.setProperty(OidcSettings.LOGIN_STRATEGY, OidcSettings.LOGIN_STRATEGY_PROVIDER_ID);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getLogin()).isEqualTo("8f63a486-6699-4f25-beef-118dd240bef8");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isNull();
  }

  @Test
  public void null_name_is_replaced_by_preferred_username() {
    UserInfo userInfo = newUserInfo();
    userInfo.setName(null);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getName()).isEqualTo("jdoo");
  }

  @Test
  public void throw_ISE_if_strategy_is_not_supported() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty(OidcSettings.LOGIN_STRATEGY, "xxx");

    expectedException.expect(IllegalStateException.class);
    expectedException.expectMessage("Login strategy not supported: xxx");
    underTest.create(userInfo);
  }

  @Test
  public void create_with_synched_groups() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty("sonar.auth.oidc.groupsSync", true);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getGroups()).containsAll(Arrays.asList("admins", "internal"));
  }

  private UserInfo newUserInfo() {
    UserInfo userInfo = null;
    try {
      return UserInfo.parse("{\"sub\":\"8f63a486-6699-4f25-beef-118dd240bef8\",\"groups\":[\"admins\",\"internal\"],"
          + "\"iss\":\"http://localhost/auth/realms/sso\",\"typ\":\"ID\",\"preferred_username\":\"jdoo\","
          + "\"given_name\":\"John\",\"aud\":\"sonarqube\",\"acr\":\"1\",\"nbf\":0,\"azp\":\"sonarqube\","
          + "\"auth_time\":1514307002,\"name\":\"John Doo\",\"exp\":1514307302,"
          + "\"session_state\":\"f57b7a35-0de4-4ac1-8d8e-a93fc8e65cb2\",\"iat\":1514307002,"
          + "\"family_name\":\"Doo\",\"jti\":\"c4a1a958-21de-47b6-b860-d0417519de00\","
          + "\"email\":\"john.doo@acme.com\"}");
    } catch (ParseException e) {
      // ignore
    }
    return userInfo;
  }

}
