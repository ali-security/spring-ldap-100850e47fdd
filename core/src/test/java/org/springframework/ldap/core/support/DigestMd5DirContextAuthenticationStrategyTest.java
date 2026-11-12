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

import org.junit.Before;
import org.junit.Test;

import org.springframework.ldap.AuthenticationException;

import javax.naming.Context;
import java.util.Hashtable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

public class DigestMd5DirContextAuthenticationStrategyTest {

	private DigestMd5DirContextAuthenticationStrategy tested;

	@Before
	public void setUp() throws Exception {
		tested = new DigestMd5DirContextAuthenticationStrategy();
	}

	@Test
	public void setupEnvironmentSetsAuthenticationPrincipalAndCredentials() {
		Hashtable<String, Object> env = new Hashtable<String, Object>();
		tested.setupEnvironment(env, "username", "pw");

		assertThat(env.get(Context.SECURITY_AUTHENTICATION)).isEqualTo("DIGEST-MD5");
		assertThat(env.get(Context.SECURITY_PRINCIPAL)).isEqualTo("username");
		assertThat(env.get(Context.SECURITY_CREDENTIALS)).isEqualTo("pw");
	}

	@Test
	public void setupEnvironmentWhenUserDnIsSetAndPasswordIsEmptyThenAuthenticationException() {
		Hashtable<String, Object> env = new Hashtable<String, Object>();
		try {
			tested.setupEnvironment(env, "username", "");
			fail("Expected AuthenticationException");
		}
		catch (AuthenticationException expected) {
			// expected
		}

		// No unauthenticated bind credentials must have been applied.
		assertThat(env.isEmpty()).isTrue();
	}

	@Test
	public void setupEnvironmentWhenUserDnIsSetAndPasswordIsNullThenAuthenticationException() {
		Hashtable<String, Object> env = new Hashtable<String, Object>();
		try {
			tested.setupEnvironment(env, "username", null);
			fail("Expected AuthenticationException");
		}
		catch (AuthenticationException expected) {
			// expected
		}

		assertThat(env.isEmpty()).isTrue();
	}

}
