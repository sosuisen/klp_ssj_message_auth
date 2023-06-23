package com.example.model.message;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.sql.DataSource;

import jakarta.annotation.Resource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.NoArgsConstructor;

/**
 * DAO for messages table
 */
@ApplicationScoped
@NoArgsConstructor(force = true)
public class MessagesDAO {
	/**
	 * JNDIで管理されたDataSourceオブジェクトは@Resourceアノテーションで
	 * 取得できます。lookup属性でJNDI名を渡します。
	 */
	@Resource(lookup = "jdbc/__default")
	private DataSource ds;

	// getAll()とserarch() のとき、JSP側へデータを渡すために用いる。
	private final MessagesModel messagesModel;

	@Inject
	public MessagesDAO(MessagesModel messagesModel) {
		 this.messagesModel = messagesModel;
	}

	public void getAll() {
		// リダイレクト先で呼ばれた場合は無視する。
		if (messagesModel.size() > 0) return;
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM messages");) {
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				int myId = rs.getInt("id");
				String name = rs.getString("name");
				String message = rs.getString("message");
				messagesModel.add(new MessageDTO(myId, name, message));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void search(String keyword) {
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
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void create(MessageDTO mesDTO) {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn
						.prepareStatement("INSERT INTO messages(name, message) VALUES(?, ?)")) {
			pstmt.setString(1, mesDTO.getName());
			pstmt.setString(2, mesDTO.getMessage());
			pstmt.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void deleteAll() {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("DELETE from messages");) {
			pstmt.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
