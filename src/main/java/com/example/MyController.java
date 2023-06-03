package com.example;

import java.net.URI;
import java.util.List;

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
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.credential.Password;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
	private static String basePath; 
			
	private final MessagesDAO messagesDAO;

	private final UsersDAO usersDAO;

	private final Models models;

	private final Pbkdf2PasswordHash passwordHash;

	private final SecurityContext securityContext;

	@Inject
	public MyController(Models models, MessagesDAO messagesDAO, UsersDAO usersDAO, Pbkdf2PasswordHash passwordHash,
			SecurityContext securityContext, MvcContext mvcContext) {
		this.models = models;
		this.messagesDAO = messagesDAO;
		this.usersDAO = usersDAO;
		this.passwordHash = passwordHash;
		passwordHash.initialize(IdentityStoreConfig.HASH_PARAMS);
		this.securityContext = securityContext;
		// staticクラスForbiddenExceptionMapperで用いるため、static変数へ代入しておく
		basePath = mvcContext.getBasePath();
	}

	@GET
	public String home() {
		return "index.jsp";
	}

	@GET
	@Path("login")
	public String getLogin(@Context HttpServletRequest request,
			@QueryParam("messages") final String messages,
			@QueryParam("errors") final String errors) {
		if (messages != null) {
			models.put("messages", List.of(messages.split(",")));
		}
		if (errors != null) {
			models.put("errors", List.of(errors.split(",")));
		}
		try {
			request.logout();
		} catch (ServletException e) {
			e.printStackTrace();
		}
		return "login.jsp";
	}

	@POST
	@Path("login")
	public String postLogin(@BeanParam UserDTO user,
			@Context HttpServletRequest request,
			@Context HttpServletResponse response)
			throws Exception {
		Credential credential = new UsernamePasswordCredential(user.getName(), new Password(user.getPassword()));
		AuthenticationStatus status = securityContext.authenticate(
				request,
				response,
				AuthenticationParameters.withParams()
						.newAuthentication(true)
						.credential(credential));

		/**
		 * NOT_DONE
		 *  認証メカニズムが呼び出されましたが、認証しないことにしました。
		 * SEND_CONTINUE
		 *  認証メカニズムが呼び出され、発信者とのマルチステップ認証ダイアログが開始されました（たとえば、発信者がログインページにリダイレクトされました）。
		 * SEND_FAILURE
		 *  認証メカニズムが呼び出されましたが、呼び出し元が正常に認証されなかったため、呼び出し元のプリンシパルは使用できません。
		 * SUCCESS
		 *  認証メカニズムが呼び出され、呼び出し元が正常に認証されました。
		 */
		switch (status) {
			case SEND_CONTINUE, NOT_DONE -> {
			}
			case SEND_FAILURE -> models.put("errors", List.of("invalid_user"));
			case SUCCESS -> {
				return "redirect:list";
			}
		}
		return "login.jsp";
	}

	@GET
	@Path("logout")
	public String getLogout(@Context HttpServletRequest request) {
		try {
			request.logout();
		} catch (ServletException e) {
			e.printStackTrace();
		}
		return "redirect:login?messages=logout";
	}

	@GET
	@Path("list")
	@RolesAllowed({ "USER", "ADMIN" })
	public String getMessage() {
		models.put("isAdmin", securityContext.isCallerInRole("ADMIN"));
		models.put("name", securityContext.getCallerPrincipal().getName());
		messagesDAO.getAll();
		return "list.jsp";
	}

	@POST
	@Path("list")
	@RolesAllowed({ "USER", "ADMIN" })
	public String postMessage(@BeanParam MessageDTO mes) {
		mes.setName(securityContext.getCallerPrincipal().getName());
		messagesDAO.create(mes);
		return "redirect:list";
	}

	@GET
	@Path("clear")
	@RolesAllowed({ "USER", "ADMIN" })
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
	@RolesAllowed({ "ADMIN" })
	public String getUsers() {
		usersDAO.getAll();
		return "users.jsp";
	}

	@POST
	@Path("users")
	@RolesAllowed({ "ADMIN" })
	public String createUsers(@BeanParam UserDTO user) {
		var hash = passwordHash.generate(user.getPassword().toCharArray());
		user.setPassword(hash);
		usersDAO.create(user);
		return "redirect:users";
	}

	@POST
	@Path("user_delete")
	@RolesAllowed({ "ADMIN" })
	public String deleteUser(@FormParam("name") String name) {
		usersDAO.delete(name);
		return "redirect:users";
	}

	@POST
	@Path("user_update")
	@RolesAllowed({ "ADMIN" })
	public String updateUser(@BeanParam UserDTO user) {
		var hash = passwordHash.generate(user.getPassword().toCharArray());
		user.setPassword(hash);
		usersDAO.update(user);
		return "redirect:users";
	}

	@Provider
	public static class ForbiddenExceptionMapper implements ExceptionMapper<ForbiddenException> {
		@Override
		public Response toResponse(ForbiddenException exception) {
			// ExceptionMapper内でのリダイレクト実行は Response.seeOther()
			return Response.seeOther(URI.create(MyController.basePath + "/login?errors=forbidden")).build();
		}
	}
}
