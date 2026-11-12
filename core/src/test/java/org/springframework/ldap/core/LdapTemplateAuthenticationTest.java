/*
 * Copyright 2005-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.ldap.core;

import org.junit.Before;
import org.junit.Test;

import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.support.LdapUtils;

import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import java.util.Hashtable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests that {@link LdapTemplate#authenticate} never reports an unauthenticated bind
 * (non-empty user DN, empty password) as a successful authentication (gh-407).
 */
public class LdapTemplateAuthenticationTest {

	private ContextSource contextSourceMock;

	private DirContext dirContextMock;

	private NamingEnumeration namingEnumerationMock;

	private Name nameMock;

	private AuthenticatedLdapEntryContextCallback entryContextCallbackMock;

	private LdapTemplate tested;

	@Before
	public void setUp() throws Exception {
		contextSourceMock = mock(ContextSource.class);
		dirContextMock = mock(LdapContext.class);
		namingEnumerationMock = mock(NamingEnumeration.class);
		nameMock = LdapUtils.emptyLdapName();
		entryContextCallbackMock = mock(AuthenticatedLdapEntryContextCallback.class);

		tested = new LdapTemplate(contextSourceMock);

		Object expectedObject = new DirContextAdapter(new BasicAttributes(), LdapUtils.newLdapName("cn=john doe"),
				LdapUtils.newLdapName("dc=jayway, dc=se"));
		SearchResult searchResult = new SearchResult("", expectedObject, new BasicAttributes());

		when(dirContextMock.search(any(Name.class), anyString(), any(SearchControls.class)))
				.thenReturn(namingEnumerationMock);
		when(namingEnumerationMock.hasMore()).thenReturn(true, false);
		when(namingEnumerationMock.next()).thenReturn(searchResult);
	}

	@Test
	public void authenticateWhenPasswordIsEmptyAndDefaultStrategyThenReturnsFalse() throws Exception {
		when(contextSourceMock.getReadOnlyContext()).thenReturn(dirContextMock);

		// A default-configured AbstractContextSource (using
		// SimpleDirContextAuthenticationStrategy) rejects empty credentials with an
		// AuthenticationException instead of performing an unauthenticated bind.
		when(contextSourceMock.getContext("cn=john doe,dc=jayway,dc=se", ""))
				.thenThrow(new AuthenticationException(
						new javax.naming.AuthenticationException("password must be provided when userDn is set")));

		boolean result = tested.authenticate(nameMock, "(ou=somevalue)", "", entryContextCallbackMock);

		verify(dirContextMock).close();

		assertThat(result).isFalse();
	}

	// Uses a real, default-configured ContextSource so the whole LdapTemplate ->
	// AbstractContextSource -> SimpleDirContextAuthenticationStrategy path is exercised.
	@Test
	public void authenticateWhenRealContextSourceAndPasswordIsEmptyThenReturnsFalse() throws Exception {
		LdapTemplate realTested = new LdapTemplate(realContextSource());

		boolean result = realTested.authenticate(nameMock, "(ou=somevalue)", "", entryContextCallbackMock);

		assertThat(result).isFalse();
		verify(entryContextCallbackMock, never())
				.executeWithContext(any(DirContext.class), any(LdapEntryIdentification.class));
	}

	@Test
	public void authenticateQueryWhenRealContextSourceAndPasswordIsEmptyThenAuthenticationException() throws Exception {
		LdapTemplate realTested = new LdapTemplate(realContextSource());

		try {
			realTested.authenticate(LdapQueryBuilder.query().base("ou=spring").filter("ou=user"), "");
			fail("Expected AuthenticationException");
		}
		catch (AuthenticationException expected) {
			// expected
		}
	}

	// Control for the tests above: the same setup authenticates when a password is given.
	@Test
	public void authenticateWhenRealContextSourceAndPasswordIsSetThenReturnsTrue() throws Exception {
		LdapTemplate realTested = new LdapTemplate(realContextSource());

		boolean result = realTested.authenticate(nameMock, "(ou=somevalue)", "password", entryContextCallbackMock);

		assertThat(result).isTrue();
		verify(entryContextCallbackMock)
				.executeWithContext(any(DirContext.class), any(LdapEntryIdentification.class));
	}

	private LdapContextSource realContextSource() {
		LdapContextSource realContextSource = new LdapContextSource() {
			@Override
			protected DirContext createContext(Hashtable<String, Object> environment) {
				return dirContextMock;
			}
		};
		realContextSource.setUrl("ldap://ldap.example.com:389");
		realContextSource.afterPropertiesSet();
		return realContextSource;
	}
}
