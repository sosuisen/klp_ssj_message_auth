package com.example.model;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

import javax.sql.DataSource;

import com.example.auth.IdentityStoreConfig;
import com.example.model.user.UserDTO;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Initialized;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;

@ApplicationScoped
@RequiredArgsConstructor(onConstructor_ = @Inject)
@Log
public class UserInitializeService {
	private final DataSource ds;
	private final Pbkdf2PasswordHash passwordHash;
	
	/**
	 * アプリケーション起動時に実行する処理を書く
	 */
	public void onStart(@Observes @Initialized(ApplicationScoped.class) Object pointless) {
		int count = -1;
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("SELECT COUNT(*) cnt FROM users");) {
			ResultSet rs = pstmt.executeQuery();
			rs.next();
			count = rs.getInt("cnt");
		} catch (Exception e) {
			log.log(java.util.logging.Level.SEVERE, "Failed to count users", e);
		}

		if (count == 0) {
			/**
			 * 初期ユーザが登録されていなければ登録
			 */
			passwordHash.initialize(IdentityStoreConfig.HASH_PARAMS);
			var initialUsers = List.of(
					new UserDTO("user", "USER", passwordHash.generate("foo".toCharArray())),
					new UserDTO("admin", "ADMIN", passwordHash.generate("foo".toCharArray())));

			for (var user : initialUsers) {
				try (
						Connection conn = ds.getConnection();
						PreparedStatement pstmt = conn
								.prepareStatement(
										"INSERT INTO users VALUES(?, ?, ?)")) {
					pstmt.setString(1, user.getName());
					pstmt.setString(2, user.getRole());
					pstmt.setString(3, user.getPassword());
					pstmt.executeUpdate();
				} catch (Exception e) {
					log.log(java.util.logging.Level.SEVERE, "Failed to insert initial users", e);
				}
			}
		}
	}
}