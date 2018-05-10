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

import static java.lang.String.format;
import static org.vaulttec.sonarqube.auth.oidc.OidcSettings.LOGIN_STRATEGY_EMAIL;
import static org.vaulttec.sonarqube.auth.oidc.OidcSettings.LOGIN_STRATEGY_PREFERRED_USERNAME;
import static org.vaulttec.sonarqube.auth.oidc.OidcSettings.LOGIN_STRATEGY_PROVIDER_ID;
import static org.vaulttec.sonarqube.auth.oidc.OidcSettings.LOGIN_STRATEGY_UNIQUE;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.sonar.api.server.ServerSide;
import org.sonar.api.server.authentication.UserIdentity;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;

/**
 * Converts OpenID Connect {@link UserInfo} to SonarQube {@link UserIdentity}.
 */
@ServerSide
public class UserIdentityFactory {

  private final OidcSettings settings;

  public UserIdentityFactory(OidcSettings settings) {
    this.settings = settings;
  }

  public UserIdentity create(UserInfo userInfo) {
    UserIdentity.Builder builder = UserIdentity.builder().setProviderLogin(userInfo.getSubject().getValue())
        .setLogin(getLogin(userInfo)).setName(getName(userInfo)).setEmail(userInfo.getEmailAddress());
    if (settings.syncGroups()) {
      builder.setGroups(getGroups(userInfo));
    }
    return builder.build();
  }

  private String getLogin(UserInfo userInfo) {
    switch (settings.loginStrategy()) {
    case LOGIN_STRATEGY_PREFERRED_USERNAME:
      return userInfo.getPreferredUsername();
    case LOGIN_STRATEGY_PROVIDER_ID:
      return userInfo.getSubject().getValue();
    case LOGIN_STRATEGY_EMAIL:
      return userInfo.getEmailAddress();
    case LOGIN_STRATEGY_UNIQUE:
      return generateUniqueLogin(userInfo);
    default:
      throw new IllegalStateException(format("Login strategy not supported: %s", settings.loginStrategy()));
    }
  }

  private String generateUniqueLogin(UserInfo userInfo) {
    return format("%s@%s", userInfo.getSubject().getValue(), OidcIdentityProvider.KEY);
  }

  private String getName(UserInfo userInfo) {
    String name = userInfo.getName();
    return name == null || name.isEmpty() ? userInfo.getPreferredUsername() : name;
  }

  private Set<String> getGroups(UserInfo userInfo) {
    List<String> groupsClaim = userInfo.getStringListClaim(settings.syncGroupsClaimName());
    return groupsClaim != null ? new HashSet<>(groupsClaim) : Collections.emptySet();
  }

}
