/*
 * OpenID Connect Authentication for SonarQube
 * Copyright (c) 2021 Torsten Juergeleit
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

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.sonar.api.CoreProperties;
import org.sonar.api.config.Configuration;
import org.sonar.api.web.ServletFilter;

public class AutoLoginFilterTest {

  private static final String SONAR_URL = "http://acme.com/sonar";

  @Test
  public void testFilter() throws Exception {
    ServletContext servletContext = mock(ServletContext.class);
    FilterConfig filterConfig = mock(FilterConfig.class);
    Configuration configurationMock = mock(Configuration.class);
    when(configurationMock.getBoolean("sonar.auth." + OidcIdentityProvider.KEY + ".enabled"))
        .thenReturn(Optional.of(true));
    when(configurationMock.get("sonar.auth." + OidcIdentityProvider.KEY + ".issuerUri"))
        .thenReturn(Optional.of("http://idp.com"));
    when(configurationMock.get("sonar.auth." + OidcIdentityProvider.KEY + ".clientId.secured"))
        .thenReturn(Optional.of("id"));
    when(configurationMock.getBoolean("sonar.auth." + OidcIdentityProvider.KEY + ".autoLogin"))
        .thenReturn(Optional.of(true));
    when(configurationMock.get(CoreProperties.SERVER_BASE_URL)).thenReturn(Optional.of(SONAR_URL));

    ServletFilter filter = new AutoLoginFilter(new OidcConfiguration(configurationMock));
    filter.init(filterConfig);
    filter.doGetPattern();

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);

    FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response).sendRedirect(SONAR_URL + "/sessions/init/" + OidcIdentityProvider.KEY + "?return_to=/projects");

    filter.destroy();
  }

  @Test
  public void testFilterDisbled() throws Exception {
    ServletContext servletContext = mock(ServletContext.class);
    FilterConfig filterConfig = mock(FilterConfig.class);
    Configuration configurationMock = mock(Configuration.class);
    when(configurationMock.getBoolean("sonar.auth." + OidcIdentityProvider.KEY + ".enabled"))
        .thenReturn(Optional.of(true));
    when(configurationMock.get("sonar.auth." + OidcIdentityProvider.KEY + ".issuerUri"))
        .thenReturn(Optional.of("http://idp.com"));
    when(configurationMock.get("sonar.auth." + OidcIdentityProvider.KEY + ".clientId.secured"))
        .thenReturn(Optional.of("id"));
    when(configurationMock.getBoolean("sonar.auth." + OidcIdentityProvider.KEY + ".autoLogin"))
        .thenReturn(Optional.of(false));
    ServletFilter filter = new AutoLoginFilter(new OidcConfiguration(configurationMock));
    filter.init(filterConfig);
    filter.doGetPattern();

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);

    FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response, never()).sendRedirect(anyString());

    filter.destroy();
  }

  @Test
  public void testFilterTemporarilyDisbled() throws Exception {
    ServletContext servletContext = mock(ServletContext.class);
    FilterConfig filterConfig = mock(FilterConfig.class);
    Configuration configurationMock = mock(Configuration.class);
    when(configurationMock.getBoolean(OidcConfiguration.ENABLED)).thenReturn(Optional.of(true));
    when(configurationMock.get(OidcConfiguration.ISSUER_URI)).thenReturn(Optional.of("http://idp.com"));
    when(configurationMock.get(OidcConfiguration.CLIENT_ID)).thenReturn(Optional.of("id"));
    when(configurationMock.getBoolean(OidcConfiguration.AUTO_LOGIN)).thenReturn(Optional.of(true));
    ServletFilter filter = new AutoLoginFilter(new OidcConfiguration(configurationMock));
    filter.init(filterConfig);
    filter.doGetPattern();

    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader("referer")).thenReturn(SONAR_URL + "/?auto-login=false");

    HttpServletResponse response = mock(HttpServletResponse.class);

    FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response, never()).sendRedirect(anyString());

    filter.destroy();
  }

}
