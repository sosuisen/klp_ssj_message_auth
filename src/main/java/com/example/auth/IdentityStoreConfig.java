package com.example.auth;

import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import jakarta.security.enterprise.identitystore.DatabaseIdentityStoreDefinition;

/**
	テーブル定義。password のサイズはハッシュ値が収まるサイズにすること。

	create table users(
  		name VARCHAR(30) PRIMARY KEY,
  		role VARCHAR(30) NOT NULL,
  		password VARCHAR(117) NOT NULL
	);
*/

//hashAlgorithmParamatersの値はEL式を使うことができます。
@DatabaseIdentityStoreDefinition(
		dataSourceLookup = "jdbc/__default",
		callerQuery = "select password from users where name = ?",
		groupsQuery = "select role from users where name = ?",
		hashAlgorithmParameters = "${identityStoreConfig.hashAlgorithmParameters}")
@Named
@ApplicationScoped
public class IdentityStoreConfig {
	/**
	 * HASH_PARAMS は UserInitializeService でも用いる
	 */
	public static Map<String, String> HASH_PARAMS = Map.of(
			"Pbkdf2PasswordHash.Iterations", "210000",
			"Pbkdf2PasswordHash.Algorithm", "PBKDF2WithHmacSHA512",
			"Pbkdf2PasswordHash.SaltSizeBytes", "32");

	public String[] getHashAlgorithmParameters() {
		return HASH_PARAMS.entrySet().stream()
				.map(e -> e.getKey() + "=" + e.getValue()).toArray(String[]::new);
	}
}