package com.example.auth;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.annotation.security.DeclareRoles;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.security.enterprise.identitystore.DatabaseIdentityStoreDefinition;

/**
	テーブル定義の例。password のサイズはハッシュ値が収まるサイズにすること。

	create table users(
  		name VARCHAR(30) PRIMARY KEY,
  		role VARCHAR(30) NOT NULL,
  		password VARCHAR(256) NOT NULL
	);
*/


@DeclareRoles({"ADMIN", "SUBADMIN", "USER"})
@DatabaseIdentityStoreDefinition(
		dataSourceLookup = "jdbc/__default",
		callerQuery = "select password from users where name = ?",
		groupsQuery = "select role from users where name = ?",
		hashAlgorithmParameters = {
				"Pbkdf2PasswordHash.Iterations=210000",
				"Pbkdf2PasswordHash.Algorithm=PBKDF2WithHmacSHA512",
				"Pbkdf2PasswordHash.SaltSizeBytes=32"
				})
@ApplicationScoped
public class IdentityStoreConfig {
	public static Map<String, String> getHashParams() {
		String[] params = IdentityStoreConfig.class.getAnnotation(DatabaseIdentityStoreDefinition.class).hashAlgorithmParameters();
		var map = new HashMap<String, String>();
		for (var param : params) {
			var pair = param.split("=");
			map.put(pair[0], pair[1]);
		}
		return map;
	}

	public static List<String> getAllRoles() {
		String[] roles = IdentityStoreConfig.class.getAnnotation(DeclareRoles.class).value();
		return Arrays.asList(roles);
	}
}