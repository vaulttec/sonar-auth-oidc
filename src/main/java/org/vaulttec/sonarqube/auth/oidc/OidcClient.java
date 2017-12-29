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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;

import org.sonar.api.server.ServerSide;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest.Builder;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.minidev.json.JSONStyle;

@ServerSide
public class OidcClient {

	private static final Logger LOGGER = Loggers.get(OidcClient.class);

	private static final ResponseType RESPONSE_TYPE_CODE = ResponseType.getDefault();
	private static final Scope SCOPE = Scope.parse("openid email profile");

	private final OidcSettings settings;

	public OidcClient(OidcSettings settings) {
		this.settings = settings;
	}

	public AuthenticationRequest getAuthenticationRequest(String callbackUrl, String state) {
		AuthenticationRequest request;
		try {
			Builder builder = new AuthenticationRequest.Builder(RESPONSE_TYPE_CODE, SCOPE, getClientId(),
			    new URI(callbackUrl));
			request = builder.endpointURI(getProviderMetadata().getAuthorizationEndpointURI()).state(State.parse(state))
			    .build();
		} catch (URISyntaxException e) {
			throw new IllegalStateException("Creating new authentication request failed", e);
		}
		LOGGER.debug("Authentication request URI: {}", request.toURI());
		return request;
	}

	public AuthorizationCode getAuthorizationCode(HttpServletRequest callbackRequest) {
		LOGGER.debug("Retrieving authorization code from callback request's query parameters: {}",
		    callbackRequest.getQueryString());
		AuthenticationResponse authResponse = null;
		try {
			HTTPRequest request = ServletUtils.createHTTPRequest(callbackRequest);
			authResponse = AuthenticationResponseParser.parse(request.getURL().toURI(), request.getQueryParameters());
		} catch (ParseException | URISyntaxException | IOException e) {
			throw new IllegalStateException("Error while parsing callback request", e);
		}
		if (authResponse instanceof AuthenticationErrorResponse) {
			ErrorObject error = ((AuthenticationErrorResponse) authResponse).getErrorObject();
			throw new IllegalStateException(
			    "Authentication request failed: " + error.toJSONObject().toJSONString(JSONStyle.LT_COMPRESS));
		}
		AuthorizationCode authorizationCode = ((AuthenticationSuccessResponse) authResponse).getAuthorizationCode();
		LOGGER.debug("Authorization code: {}", authorizationCode.getValue());
		return authorizationCode;
	}

	UserInfo getUserInfo(AuthorizationCode authorizationCode, String callbackUrl) {
		LOGGER.debug("Retrieving OIDC tokens with user info claims set from {}",
		    getProviderMetadata().getTokenEndpointURI());
		TokenResponse tokenResponse;
		try {
			TokenRequest request = new TokenRequest(getProviderMetadata().getTokenEndpointURI(),
			    new ClientSecretBasic(getClientId(), getClientSecret()),
			    new AuthorizationCodeGrant(authorizationCode, new URI(callbackUrl)));
			HTTPResponse response = request.toHTTPRequest().send();
			tokenResponse = OIDCTokenResponseParser.parse(response);
		} catch (URISyntaxException | IOException | ParseException e) {
			throw new IllegalStateException("Retrieving access token failed", e);
		}
		if (tokenResponse instanceof TokenErrorResponse) {
			throw new IllegalStateException("Token request failed: " + ((TokenErrorResponse) tokenResponse).toJSONObject());
		}

		UserInfo userInfo;
		try {
			userInfo = new UserInfo(((OIDCTokenResponse) tokenResponse).getOIDCTokens().getIDToken().getJWTClaimsSet());
		} catch (java.text.ParseException e) {
			throw new IllegalStateException("Parsing ID token failed", e);
		}
		LOGGER.debug("User info: {}", userInfo.toJSONObject());
		return userInfo;
	}

	private OIDCProviderMetadata getProviderMetadata() {
		OIDCProviderMetadata providerMetadata;
		try {
			providerMetadata = OIDCProviderMetadata.parse(settings.providerConfiguration());
		} catch (ParseException e) {
			throw new IllegalStateException("Invalid OpenID Connect provider configuration", e);
		}
		return providerMetadata;
	}

	private ClientID getClientId() {
		return new ClientID(settings.clientId());
	}

	private Secret getClientSecret() {
		String secret = settings.clientSecret();
		return secret == null ? new Secret("") : new Secret(secret);
	}

}
