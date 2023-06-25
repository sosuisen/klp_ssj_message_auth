package com.example;

import java.net.URI;

import com.example.auth.IdentityStoreConfig;
import com.example.model.message.MessageDTO;
import com.example.model.message.MessagesDAO;
import com.example.model.user.UserDTO;
import com.example.model.user.UsersDAO;

import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.mvc.Controller;
import jakarta.mvc.Models;
import jakarta.mvc.MvcContext;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
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
@Path("/")
public class MyController {
	private final Models models;

	private final MessagesDAO messagesDAO;

	private final UsersDAO usersDAO;

	private final Pbkdf2PasswordHash passwordHash;

	@Inject
	public MyController(Models models, MessagesDAO messagesDAO, UsersDAO usersDAO, Pbkdf2PasswordHash passwordHash,
			MvcContext mvcContext) {
		this.models = models;
		this.messagesDAO = messagesDAO;
		this.usersDAO = usersDAO;
		this.passwordHash = passwordHash;
		passwordHash.initialize(IdentityStoreConfig.HASH_PARAMS);
	}

	@GET
	public String home() {
		return "index.jsp";
	}

	@GET
	@Path("login")
	public String getLogin(@QueryParam("error") final String error) {
		models.put("error", error);
		return "login.jsp";
	}

	@GET
	@Path("logout")
	public String getLogout(@Context HttpServletRequest req) {
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
	@RolesAllowed({ "USER", "ADMIN" })
	public String getMessage(@Context HttpServletRequest req) {
		models.put("req", req);		
		messagesDAO.getAll();
		return "list.jsp";
	}

	@POST
	@Path("list")
	@RolesAllowed({ "USER", "ADMIN" })
	public String postMessage(@BeanParam MessageDTO mes, @Context HttpServletRequest req) {
		mes.setName(req.getRemoteUser());
		messagesDAO.create(mes);
		return "redirect:list";
	}

	@GET
	@Path("clear")
	@RolesAllowed({ "ADMIN" })
	public String clearMessage() {
		messagesDAO.deleteAll();
		return "redirect:list";
	}

	@POST
	@Path("search")
	@RolesAllowed({ "USER", "ADMIN" })
	public String postSearch(@FormParam("keyword") String keyword) {
		messagesDAO.search(keyword);
		// messagesDAO が @RedirectScoped なので、リダイレクト先でも参照可能。
		return "redirect:list";
	}

	@GET
	@Path("users")
	@RolesAllowed("ADMIN")
	public String getUsers() {
		usersDAO.getAll();
		return "users.jsp";
	}

	@POST
	@Path("users")
	@RolesAllowed("ADMIN")
	public String createUsers(@BeanParam UserDTO user) {
		var hash = passwordHash.generate(user.getPassword().toCharArray());
		user.setPassword(hash);
		usersDAO.create(user);
		return "redirect:users";
	}

	@POST
	@Path("user_delete")
	@RolesAllowed("ADMIN")
	public String deleteUser(@FormParam("name") String name) {
		usersDAO.delete(name);
		return "redirect:users";
	}

	@POST
	@Path("user_update")
	@RolesAllowed("ADMIN")
	public String updateUser(@BeanParam UserDTO user) {
		if (!user.getPassword().equals("")) {
			var hash = passwordHash.generate(user.getPassword().toCharArray());
			user.setPassword(hash);
		}
		usersDAO.update(user);
		return "redirect:users";
	}

	/*
	 * 権限がないページへのアクセスは 403 Forbidden になるため、
	 * 対応するExceptionMapperを追加
	 */
	@Provider
	public static class ForbiddenExceptionMapper implements ExceptionMapper<ForbiddenException> {
		private HttpServletRequest req;

		@Inject
		public ForbiddenExceptionMapper(@Context HttpServletRequest req) {
			this.req = req;
		}

		@Override
		public Response toResponse(ForbiddenException exception) {
			try {
				req.logout();
				req.getSession().invalidate();
			} catch (ServletException e) {
				e.printStackTrace();
			}
			// ExceptionMapper内でのリダイレクト実行は Response.seeOther()
			return Response.seeOther(URI.create(req.getRequestURL().toString() + "?error=forbidden")).build();
		}
	}
}
