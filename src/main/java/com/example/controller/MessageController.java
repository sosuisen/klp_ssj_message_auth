package com.example.controller;

import java.sql.SQLException;
import java.util.logging.Level;

import com.example.model.message.MessageDTO;
import com.example.model.message.MessagesDAO;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.mvc.Controller;
import jakarta.mvc.Models;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;

/**
 * Jakarta MVCのコンロトーラクラスです。@Controllerアノテーションを付けましょう。
 * 
 * コントローラクラスはCDI beanであることが必須で、必ず@RequestScopedを付けます。
 * 
 * CDI beanには引数のないコンストラクタが必須なので、
 * Lombokの@NoArgsConstructorで空っぽのコンストラクタを作成します。
 * 
 * @Path はこのクラス全体が扱うURLのパスで、JAX-RSのアノテーションです。
 * これは @ApplicationPath からの相対パスとなります。
 * パスの先頭の/と末尾の/はあってもなくても同じです。
 */
@Controller
@RequestScoped
@NoArgsConstructor(force = true)
@RequiredArgsConstructor(onConstructor_ = @Inject)
@PermitAll
@Log
@Path("/")
public class MessageController {
	private final Models models;
	private final MessagesDAO messagesDAO;
	private final HttpServletRequest req;

	@PostConstruct
	public void afterInit() {
		log.log(Level.INFO, "[user]%s, [ip]%s [url]%s".formatted(
				req.getRemoteUser(),
				req.getRemoteAddr(),
				req.getRequestURL().toString()));
	}

	/**
	 * 以下は認証不要（web.xmlで設定）
	 */
	@GET
	public String home() {
		models.put("appName", "メッセージアプリ");
		return "index.jsp";
	}

	@GET
	@Path("login")
	public String login(@QueryParam("error") final String error) {
		models.put("error", error);
		return "login.jsp";
	}

	/**
	 * 以下は要認証（web.xmlで設定）
	 */
	@GET
	@Path("logout")
	public String logout() {
		try {
			req.logout(); // ログアウトする
			req.getSession().invalidate(); // セッションを無効化する
		} catch (ServletException e) {
			log.log(Level.SEVERE, "Failed to logout", e);
		}
		return "redirect:/";
	}

	@GET
	@Path("list")
	public String getMessage() throws SQLException {
		models.put("req", req);	
		models.put("messages", messagesDAO.getAll());
		return "list.jsp";
	}

	@POST
	@Path("list")
	public String postMessage(@BeanParam MessageDTO mes) throws SQLException {
		mes.setName(req.getRemoteUser());
		messagesDAO.create(mes);
		return "redirect:list";
	}

	@GET
	@Path("clear")
	@RolesAllowed("ADMIN")
	public String clearMessage() throws SQLException {
		messagesDAO.deleteAll();
		return "redirect:list";
	}

	@POST
	@Path("search")
	public String postSearch(@FormParam("keyword") String keyword) throws SQLException {
		models.put("messages", messagesDAO.search(keyword));
		return "list.jsp";
	}
	
	@GET
	@Path("manager")
	@RolesAllowed("ADMIN")
	public String getManager() {
		return "manager.jsp";
	}
}
