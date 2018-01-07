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

import static org.vaulttec.sonarqube.auth.oidc.OidcSettings.LOGIN_STRATEGY_DEFAULT_VALUE;

import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.Settings;

public abstract class AbstractOidcTest {

	public static final String ISSUER_URI = "https://oidc.org";
	public static final String CALLBACK_URL = "http://localhost/callback";
	public static final String STATE = "state";
	public static final String VALID_CODE = "valid_code";
	public static final String INVALID_CODE = "invalid_code";
	public static final String INVALID_URL = "htp: / invalid . com";

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	protected Settings settings = new Settings();
	protected OidcSettings oidcSettings = new OidcSettings(settings);

	protected void setSettings(boolean enabled) {
		setSettings(enabled, ISSUER_URI);
	}

	protected void setSettings(boolean enabled, String issuerUri) {
		if (enabled) {
			settings.setProperty("sonar.auth.oidc.providerConfiguration", getProviderConfiguration(issuerUri));
			settings.setProperty("sonar.auth.oidc.clientId.secured", "id");
			settings.setProperty("sonar.auth.oidc.clientSecret.secured", "secret");
			settings.setProperty("sonar.auth.oidc.issuerUri", "http://localhost/auth/sso");
			settings.setProperty("sonar.auth.oidc.loginStrategy", LOGIN_STRATEGY_DEFAULT_VALUE);
			settings.setProperty("sonar.auth.oidc.enabled", true);
		} else {
			settings.setProperty("sonar.auth.oidc.enabled", false);
		}
	}

	protected String getProviderConfiguration(String issuerUri) {
		return "{\"issuer\":\"" + issuerUri + "\","
		    + "\"authorization_endpoint\":\"" + issuerUri + "/protocol/openid-connect/auth" + "\","
		    + "\"token_endpoint\":\"" + issuerUri + "/protocol/openid-connect/token\"," + "\"userinfo_endpoint\":\""
		    + issuerUri + "/protocol/openid-connect/userinfo\"," + "\"jwks_uri\":\"" + issuerUri
		    + "/protocol/openid-connect/certs\","
		    + "\"grant_types_supported\":[\"authorization_code\",\"implicit\",\"refresh_token\",\"password\",\"client_credentials\"],"
		    + "\"response_types_supported\":[\"code\",\"none\",\"id_token\",\"token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"],"
		    + "\"subject_types_supported\":[\"public\",\"pairwise\"],"
		    + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
		    + "\"userinfo_signing_alg_values_supported\":[\"RS256\"],"
		    + "\"request_object_signing_alg_values_supported\":[\"none\",\"RS256\"],"
		    + "\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],"
		    + "\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\"],"
		    + "\"token_endpoint_auth_signing_alg_values_supported\":[\"RS256\"],"
		    + "\"claims_supported\":[\"sub\",\"iss\",\"auth_time\",\"name\",\"given_name\",\"family_name\",\"preferred_username\",\"email\"],"
		    + "\"claim_types_supported\":[\"normal\"]," + "\"claims_parameter_supported\":false,"
		    + "\"scopes_supported\":[\"openid\",\"offline_access\"]," + "\"request_parameter_supported\":true,"
		    + "\"request_uri_parameter_supported\":true}";
	}

}
