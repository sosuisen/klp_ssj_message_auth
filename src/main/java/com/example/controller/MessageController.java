package com.example.controller;

import com.example.model.message.MessageDTO;
import com.example.model.message.MessagesDAO;

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

/**
 * Jakarta MVCのコンロトーラクラスです。@Controllerアノテーションを付けてください。
 * 
 * 加えて、コントローラクラスは必ず@RequestScopedを付けてCDI Beanにします。
 * 
 * CDI beanには引数のないコンストラクタが必須なので、
 * Lombokの@NoArgsConstructorで空っぽのコンストラクタを作成します。
 * ただし、このクラスは宣言時に初期化してないfinalフィールドを持つため、
 * このままだとフィールドが初期化されない可能性があってコンパイルエラーとなります。
 * これを防ぐには(force=true)指定が必要です。
 */
@Controller
@RequestScoped
@NoArgsConstructor(force = true)
@PermitAll
@Path("/")
public class MessageController {
	private final Models models;
	private final MessagesDAO messagesDAO;
	private final HttpServletRequest req;

	@Inject
	public MessageController(Models models, MessagesDAO messagesDAO, HttpServletRequest req) {
		this.models = models;
		this.messagesDAO = messagesDAO;
		this.req = req;
	}

	/**
	 * 以下は認証不要（web.xmlで設定）
	 */
	@GET
	public String home() {
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
			e.printStackTrace();
		}
		return "redirect:/";
	}

	@GET
	@Path("list")
	public String getMessages() {
		models.put("req", req);		
		messagesDAO.getAll();
		return "list.jsp";
	}

	@POST
	@Path("list")
	public String postMessage(@BeanParam MessageDTO mes) {
		mes.setName(req.getRemoteUser());
		messagesDAO.create(mes);
		return "redirect:list";
	}

	@GET
	@Path("clear")
	@RolesAllowed("ADMIN")
	public String clearMessages() {
		messagesDAO.deleteAll();
		return "redirect:list";
	}

	@POST
	@Path("search")
	public String searchMessages(@FormParam("keyword") String keyword) {
		messagesDAO.search(keyword);
		// messagesModel が @RedirectScoped なので、リダイレクト先でも参照可能。
		return "redirect:list";
	}
}
