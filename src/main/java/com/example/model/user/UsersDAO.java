package com.example.model.user;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.sql.DataSource;

import jakarta.annotation.Resource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.NoArgsConstructor;

/**
 * DAO for users table
 */
@ApplicationScoped
@NoArgsConstructor(force = true)
public class UsersDAO {
	/**
	 * JNDIで管理されたDataSourceオブジェクトは@Resourceアノテーションで
	 * 取得できます。lookup属性でJNDI名を渡します。
	 */
	@Resource(lookup = "jdbc/__default")
	private DataSource ds;

	private final UsersModel usersModel;

	@Inject
	public UsersDAO(UsersModel usersModel) {
		this.usersModel = usersModel;
	}

	public void getAll() {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("SELECT name, role FROM users");) {
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				usersModel.add(new UserDTO(rs.getString("name"), rs.getString("role"), ""));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public UserDTO get(String name) {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE name=?");) {
			pstmt.setString(1, name);
			ResultSet rs = pstmt.executeQuery();
			rs.next();
			return new UserDTO(rs.getString("name"), rs.getString("role"), rs.getString("password"));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public void create(UserDTO userDTO) {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn
						.prepareStatement("INSERT INTO users VALUES(?, ?, ?)")) {
			pstmt.setString(1, userDTO.getName());
			pstmt.setString(2, userDTO.getRole());
			pstmt.setString(3, userDTO.getPassword());
			pstmt.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void deleteAll() {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("DELETE FROM users");) {
			pstmt.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void delete(String name) {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("DELETE FROM users WHERE name=?");) {
			pstmt.setString(1, name);
			pstmt.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void update(UserDTO userDTO) {
		try (
				Connection conn = ds.getConnection()) {
			if (userDTO.getPassword().isEmpty())
				try (PreparedStatement pstmt = conn.prepareStatement("UPDATE users SET role=? where name=?")) {
					pstmt.setString(1, userDTO.getRole());
					pstmt.setString(2, userDTO.getName());
					pstmt.executeUpdate();

				}
			else
				try (PreparedStatement pstmt = conn
						.prepareStatement("UPDATE users SET role=?,password=? where name=?")) {
					pstmt.setString(1, userDTO.getRole());
					pstmt.setString(2, userDTO.getPassword());
					pstmt.setString(3, userDTO.getName());
					pstmt.executeUpdate();
				}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
