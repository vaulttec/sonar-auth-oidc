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
import static java.lang.String.valueOf;
import static org.sonar.api.CoreProperties.CATEGORY_SECURITY;
import static org.sonar.api.PropertyType.BOOLEAN;
import static org.sonar.api.PropertyType.SINGLE_SELECT_LIST;
import static org.sonar.api.PropertyType.STRING;
import static org.sonar.api.PropertyType.TEXT;

import java.util.Arrays;
import java.util.List;

import javax.annotation.CheckForNull;

import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.config.Settings;
import org.sonar.api.server.ServerSide;

@ServerSide
public class OidcSettings {

  private static final String CATEGORY = CATEGORY_SECURITY;
  private static final String SUBCATEGORY = "oidc";

  private static final String ENABLED = "sonar.auth.oidc.enabled";
  private static final String ALLOW_USERS_TO_SIGN_UP = "sonar.auth.oidc.allowUsersToSignUp";
  private static final String PROVIDER_CONFIGURATION = "sonar.auth.oidc.providerConfiguration";
  private static final String CLIENT_ID = "sonar.auth.oidc.clientId.secured";
  private static final String CLIENT_SECRET = "sonar.auth.oidc.clientSecret.secured";

  static final String LOGIN_STRATEGY = "sonar.auth.oidc.loginStrategy";
  static final String LOGIN_STRATEGY_UNIQUE = "Unique";
  static final String LOGIN_STRATEGY_PROVIDER_ID = "Same as OpenID Connect login";
  static final String LOGIN_STRATEGY_PREFERRED_USERNAME = "Preferred username";
  static final String LOGIN_STRATEGY_EMAIL = "Email";
  static final String LOGIN_STRATEGY_CUSTOM_CLAIM = "Custom claim";
  static final String LOGIN_STRATEGY_DEFAULT_VALUE = LOGIN_STRATEGY_PREFERRED_USERNAME;

  private static final String GROUPS_SYNC = "sonar.auth.oidc.groupsSync";
  private static final String GROUPS_SYNC_CLAIM_NAME = "sonar.auth.oidc.groupsSync.claimName";
  private static final String GROUPS_SYNC_CLAIM_NAME_DEFAULT_VALUE = "groups";

  private static final String LOGIN_STRATEGY_CUSTOM_CLAIM_NAME = "sonar.auth.oidc.loginStrategy.customClaimName";
  private static final String LOGIN_STRATEGY_CUSTOM_CLAIM_NAME_DEFAULT_VALUE = "upn";

  private final Settings settings;

  public OidcSettings(Settings settings) {
    this.settings = settings;
  }

  public boolean isEnabled() {
    return settings.getBoolean(ENABLED) && providerConfiguration() != null && clientId() != null;
  }

  @CheckForNull
  public String providerConfiguration() {
    return settings.getString(PROVIDER_CONFIGURATION);
  }

  @CheckForNull
  public String clientId() {
    return settings.getString(CLIENT_ID);
  }

  public String clientSecret() {
    return settings.getString(CLIENT_SECRET);
  }

  public boolean allowUsersToSignUp() {
    return settings.getBoolean(ALLOW_USERS_TO_SIGN_UP);
  }

  public String loginStrategy() {
    return settings.getString(LOGIN_STRATEGY);
  }

  public String loginStrategyClaimName() {
    return settings.getString(LOGIN_STRATEGY_CUSTOM_CLAIM_NAME);
  }

  public boolean syncGroups() {
    return settings.getBoolean(GROUPS_SYNC);
  }

  public String syncGroupsClaimName() {
    return settings.getString(GROUPS_SYNC_CLAIM_NAME);
  }

  public static List<PropertyDefinition> definitions() {
    int index = 1;
    return Arrays.asList(
        PropertyDefinition.builder(ENABLED).name("Enabled")
            .description(
                "Enable OpenID Connect users to login. Value is ignored if client ID and secret are not defined.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(BOOLEAN).defaultValue(valueOf(false)).index(index++)
            .build(),
        PropertyDefinition.builder(PROVIDER_CONFIGURATION).name("OpenID Connect Provider configuration")
            .description("The endpoint configuration of an OpenID Connect provider."
                + " This metadata is retrived from the provider in JSON format via the path \"/.well-known/openid-configuration\".")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(TEXT).index(index++).build(),
        PropertyDefinition.builder(CLIENT_ID).name("Client ID").description("The ID of an OpenID Connect Client.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).index(index++).build(),
        PropertyDefinition.builder(CLIENT_SECRET).name("Client secret")
            .description("The shared secret of a non-public client. "
                + "This is only needed for an OpenID Connect client with access type \"confidential\".")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).index(index++).build(),
        PropertyDefinition.builder(ALLOW_USERS_TO_SIGN_UP).name("Allow users to sign-up").description(
            "Allow new users to authenticate. When set to 'false', only existing users will be able to authenticate to the server.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(BOOLEAN).defaultValue(valueOf(true)).index(index++)
            .build(),
        PropertyDefinition.builder(LOGIN_STRATEGY).name("Login generation strategy").description(format(
            "When the login strategy is set to '%s', the user's login will be auto-generated the first time so that it is unique."
                + " When the login strategy is set to '%s', the user's login will be the OpenID Connect provider's internal user ID."
                + " When the login strategy is set to '%s', the user's login will be the OpenID Connect provider's user email."
                + " When the login strategy is set to '%s', the user's login will be the OpenID Connect provider's user name."
                + " When the login strategy is set to '%s', the user's login will be a custom claim in OpenID Connect provider's token.",
            LOGIN_STRATEGY_UNIQUE, LOGIN_STRATEGY_PROVIDER_ID, LOGIN_STRATEGY_EMAIL, LOGIN_STRATEGY_PREFERRED_USERNAME, LOGIN_STRATEGY_CUSTOM_CLAIM)).category(CATEGORY)
            .subCategory(SUBCATEGORY).type(SINGLE_SELECT_LIST).defaultValue(LOGIN_STRATEGY_DEFAULT_VALUE)
            .options(LOGIN_STRATEGY_UNIQUE, LOGIN_STRATEGY_PROVIDER_ID, LOGIN_STRATEGY_EMAIL, LOGIN_STRATEGY_PREFERRED_USERNAME, LOGIN_STRATEGY_CUSTOM_CLAIM)
            .index(index++).build(),
        PropertyDefinition.builder(GROUPS_SYNC).name("Synchronize groups")
            .description("For each of his Open ID Connect userinfo groups claim entries,"
                + " the user will be associated to a group with the same name (if it exists) in SonarQube.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(BOOLEAN).defaultValue(valueOf(false)).index(index++)
            .build(),
        PropertyDefinition.builder(GROUPS_SYNC_CLAIM_NAME).name("Groups claim name")
            .description("Name of the claim in the Open ID Connect userinfo holding the user's groups.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).defaultValue(GROUPS_SYNC_CLAIM_NAME_DEFAULT_VALUE)
            .index(index++).build(),
        PropertyDefinition.builder(LOGIN_STRATEGY_CUSTOM_CLAIM_NAME).name("Login stategy custom claim")
            .description("Name of the claim in case login generation strategy is set to custom claim.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).defaultValue(LOGIN_STRATEGY_CUSTOM_CLAIM_NAME_DEFAULT_VALUE)
            .index(index++).build());
  }

}
