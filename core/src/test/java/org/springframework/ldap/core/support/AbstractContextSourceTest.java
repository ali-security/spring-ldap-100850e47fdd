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

package org.springframework.ldap.core.support;

import org.junit.Test;
import org.springframework.ldap.AuthenticationException;

import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapName;
import java.util.Hashtable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;

/**
 * @author Mattias Hellborg Arthursson
 */
public class AbstractContextSourceTest {

    @Test
    public void testFormatForUrlNormal() throws InvalidNameException {
        LdapName ldapName = new LdapName("dc=261consulting, dc=com");

        String result = AbstractContextSource.formatForUrl(ldapName);
        assertThat(result).isEqualTo("dc=261consulting,dc=com");
    }

    @Test
    public void testFormatForUrlNormalWithQuestionMark() throws InvalidNameException {
        LdapName ldapName = new LdapName("dc=261consulting?, dc=com");

        String result = AbstractContextSource.formatForUrl(ldapName);
        assertThat(result).isEqualTo("dc=261consulting%3F,dc=com");
    }

    @Test
    public void testFormatForUrlWithSpace() throws InvalidNameException {
        LdapName ldapName = new LdapName("ou=some department, dc=261consulting, dc=com");

        String result = AbstractContextSource.formatForUrl(ldapName);
        assertThat(result).isEqualTo("ou=some%20department,dc=261consulting,dc=com");
    }

    @Test
    public void testFormatForUrlEmpty() throws InvalidNameException {
        LdapName ldapName = new LdapName("");

        String result = AbstractContextSource.formatForUrl(ldapName);
        assertThat(result).isEqualTo("");
    }

    @Test
    public void getContextWhenUserDnIsSetAndPasswordIsEmptyThenAuthenticationException() {
        LdapContextSource tested = contextSource(null);
        try {
            tested.getContext("cn=admin", "");
            fail("Expected AuthenticationException");
        }
        catch (AuthenticationException expected) {
            // expected
        }
    }

    @Test
    public void getContextWhenUserDnIsSetAndPasswordIsNullThenAuthenticationException() {
        LdapContextSource tested = contextSource(null);
        try {
            tested.getContext("cn=admin", null);
            fail("Expected AuthenticationException");
        }
        catch (AuthenticationException expected) {
            // expected
        }
    }

    // Without the check the authenticated environment carries a userDn together with
    // blank credentials, which an LDAP server interprets as an unauthenticated bind.
    @Test
    public void getAuthenticatedEnvWhenUserDnIsSetAndPasswordIsEmptyThenAuthenticationException() {
        LdapContextSource tested = contextSource(null);
        try {
            Hashtable<String, Object> env = tested.getAuthenticatedEnv("cn=Some User", "");
            fail("Expected AuthenticationException but got credentials "
                    + env.get(Context.SECURITY_CREDENTIALS) + " for principal "
                    + env.get(Context.SECURITY_PRINCIPAL));
        }
        catch (AuthenticationException expected) {
            // expected
        }
    }

    @Test
    public void getAuthenticatedEnvWhenUserDnAndPasswordAreEmptyThenSucceeds() {
        LdapContextSource tested = contextSource(null);
        Hashtable<String, Object> env = tested.getAuthenticatedEnv("", "");

        assertThat(env.get(Context.SECURITY_AUTHENTICATION)).isEqualTo("simple");
        assertThat(env.get(Context.SECURITY_PRINCIPAL)).isEqualTo("");
        assertThat(env.get(Context.SECURITY_CREDENTIALS)).isEqualTo("");
    }

    @Test
    public void getContextWhenDigestMd5StrategyAndPasswordIsEmptyThenAuthenticationException() {
        LdapContextSource tested = contextSource(new DigestMd5DirContextAuthenticationStrategy());
        try {
            tested.getContext("username", "");
            fail("Expected AuthenticationException");
        }
        catch (AuthenticationException expected) {
            // expected
        }
    }

    // Certificate based authentication does not use the password at all.
    @Test
    public void getAuthenticatedEnvWhenExternalTlsStrategyAndPasswordIsEmptyThenSucceeds() {
        LdapContextSource tested = contextSource(new ExternalTlsDirContextAuthenticationStrategy());
        Hashtable<String, Object> env = tested.getAuthenticatedEnv("cn=Some User", "");

        assertThat(env.get(Context.SECURITY_CREDENTIALS)).isNull();
    }

    private LdapContextSource contextSource(DirContextAuthenticationStrategy authenticationStrategy) {
        final DirContext dirContextMock = mock(DirContext.class);
        LdapContextSource contextSource = new LdapContextSource() {
            @Override
            protected DirContext createContext(Hashtable<String, Object> environment) {
                return dirContextMock;
            }
        };
        contextSource.setUrl("ldap://ldap.example.com:389");
        contextSource.setUserDn("cn=service");
        contextSource.setPassword("secret");
        if (authenticationStrategy != null) {
            contextSource.setAuthenticationStrategy(authenticationStrategy);
        }
        contextSource.afterPropertiesSet();
        return contextSource;
    }
}
