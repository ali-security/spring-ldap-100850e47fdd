package org.springframework.ldap.core.support;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import org.springframework.ldap.AuthenticationException;

import javax.naming.directory.DirContext;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsResponse;
import java.util.Hashtable;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultTlsDirContextAuthenticationStrategyTests {
	@Mock
	private LdapContext context;

	@Mock
	private StartTlsResponse tlsResponse;

	private DefaultTlsDirContextAuthenticationStrategy strategy = new DefaultTlsDirContextAuthenticationStrategy();

	// gh-430, gh-502
	@Test
	public void applyAuthenticationThenLookupInvoked() throws Exception {
		this.strategy.applyAuthentication(this.context, "username", "password");

		verify(this.context).lookup("");
	}

	@Test
	public void applyAuthenticationWhenUserDnIsSetAndPasswordIsEmptyThenAuthenticationException() throws Exception {
		try {
			this.strategy.applyAuthentication(this.context, "username", "");
			fail("Expected AuthenticationException");
		}
		catch (AuthenticationException expected) {
			// expected
		}

		// The unauthenticated bind must never reach the server.
		verifyZeroInteractions(this.context);
	}

	@Test
	public void applyAuthenticationWhenUserDnIsSetAndPasswordIsNullThenAuthenticationException() throws Exception {
		try {
			this.strategy.applyAuthentication(this.context, "username", null);
			fail("Expected AuthenticationException");
		}
		catch (AuthenticationException expected) {
			// expected
		}

		verifyZeroInteractions(this.context);
	}

	@Test
	public void getContextWhenUserDnIsSetAndPasswordIsEmptyThenAuthenticationException() throws Exception {
		LdapContextSource contextSource = tlsContextSource();
		try {
			contextSource.getContext("username", "");
			fail("Expected AuthenticationException");
		}
		catch (AuthenticationException expected) {
			// expected
		}

		// The unauthenticated bind must never reach the server.
		verify(this.context, never()).addToEnvironment(anyString(), any());
		verify(this.context, never()).lookup(anyString());
	}

	@Test
	public void getContextWhenUserDnIsSetAndPasswordIsNullThenAuthenticationException() throws Exception {
		LdapContextSource contextSource = tlsContextSource();
		try {
			contextSource.getContext("username", null);
			fail("Expected AuthenticationException");
		}
		catch (AuthenticationException expected) {
			// expected
		}

		verify(this.context, never()).addToEnvironment(anyString(), any());
		verify(this.context, never()).lookup(anyString());
	}

	private LdapContextSource tlsContextSource() throws Exception {
		// Lets the StartTLS negotiation complete, so that without the empty password
		// check the unauthenticated bind would go through and return a context.
		when(this.context.extendedOperation(any(ExtendedRequest.class))).thenReturn(this.tlsResponse);

		LdapContextSource contextSource = new LdapContextSource() {
			@Override
			protected DirContext createContext(Hashtable<String, Object> environment) {
				return context;
			}
		};
		contextSource.setUrl("ldap://ldap.example.com:389");
		contextSource.setAuthenticationStrategy(this.strategy);
		contextSource.afterPropertiesSet();
		return contextSource;
	}
}