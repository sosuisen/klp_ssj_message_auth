package com.example.model.message;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import javax.sql.DataSource;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

/*
 * メッセージアプリからデータベースへのリクエストを仲介する
 * DAO（Data Access Object）クラスです。
 */
@ApplicationScoped
@NoArgsConstructor(force = true)
@RequiredArgsConstructor(onConstructor_ = @Inject)
public class MessagesDAO {
	private final DataSource ds;

	public ArrayList<MessageDTO> getAll() throws SQLException {
		var messagesModel = new ArrayList<MessageDTO>();
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM messages");) {
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				messagesModel.add(new MessageDTO(
						rs.getInt("id"),
						rs.getString("name"),
						rs.getString("message")));
			}
		}
		return messagesModel;
	}

	public ArrayList<MessageDTO> search(String keyword) throws SQLException {
		var messagesModel = new ArrayList<MessageDTO>();
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM messages WHERE message LIKE ?");) {
			// 部分一致で検索する場合、LIKEの後には　%キーワード%
			// この%はバインド時に与える必要があります。
			pstmt.setString(1, "%" + keyword + "%");
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				messagesModel.add(new MessageDTO(
						rs.getInt("id"),
						rs.getString("name"),
						rs.getString("message")));
			}
		}
		return messagesModel;
	}

	public void create(MessageDTO mesDTO) throws SQLException {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn
						.prepareStatement("INSERT INTO messages(name, message) VALUES(?, ?)");) {
			pstmt.setString(1, mesDTO.getName());
			pstmt.setString(2, mesDTO.getMessage());
			pstmt.executeUpdate();
		}
	}

	public void deleteAll() throws SQLException {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("DELETE from messages");) {
			pstmt.executeUpdate();
		}
	}
}
