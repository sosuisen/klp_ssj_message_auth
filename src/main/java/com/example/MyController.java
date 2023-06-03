package com.example;

import java.util.Map;

import com.example.model.ErrorBean;
import com.example.model.LoginUserModel;
import com.example.model.message.MessageDTO;
import com.example.model.message.MessagesDAO;
import com.example.model.user.UserDTO;
import com.example.model.user.UsersDAO;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.mvc.Controller;
import jakarta.mvc.Models;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;
import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
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
	private final MessagesDAO messagesDAO;

	private final UsersDAO usersDAO;
	
	private final Models models;

	private final LoginUserModel loginUserModel;

	private final ErrorBean errorBean;

	private final Pbkdf2PasswordHash passwordHash;

	private Map<String, String> HASH_PARAMS = Map.of(
			"Pbkdf2PasswordHash.Iterations", "10000",
			"Pbkdf2PasswordHash.Algorithm", "PBKDF2WithHmacSHA512",
			"Pbkdf2PasswordHash.SaltSizeBytes", "128");

	@Inject
	public MyController(Models models, MessagesDAO messagesDAO, UsersDAO usersDAO, LoginUserModel loginUserModel,
			ErrorBean errorBean, Pbkdf2PasswordHash passwordHash) {
		this.models = models;
		this.messagesDAO = messagesDAO;
		this.usersDAO = usersDAO;
		this.loginUserModel = loginUserModel;
		this.errorBean = errorBean;
		this.passwordHash = passwordHash;
		passwordHash.initialize(HASH_PARAMS);
	}

	@GET
	public String home() {
		models.put("appName", "メッセージアプリ");
		return "index.jsp";
	}

	@GET
	@Path("list")
	public String getMessage() {
		if (loginUserModel.getName() == null) {
			return "redirect:login";
		}
		messagesDAO.getAll();
		return "list.jsp";
	}

	@POST
	@Path("list")
	public String postMessage(@BeanParam MessageDTO mes) {
		mes.setName(loginUserModel.getName());
		messagesDAO.create(mes);
		return "redirect:list";
	}

	@GET
	@Path("clear")
	public String clearMessage() {
		messagesDAO.deleteAll();
		return "redirect:list";
	}

	@GET
	@Path("login")
	public String getLogin() {
		loginUserModel.setName(null);
		return "login.jsp";
	}

	@POST
	@Path("login")
	public String postLogin(@BeanParam UserDTO userDTO) {
		UserDTO user = usersDAO.get(userDTO.getName());
		if (user == null) return "ユーザ名またはパスワードが異なります";
		
		if(passwordHash.verify(userDTO.getPassword().toCharArray(), user.getPassword())) {
			loginUserModel.setName(userDTO.getName());
			return "redirect:list";
		}
		errorBean.setMessage("ユーザ名またはパスワードが異なります");
		return "redirect:login";
	}

	@POST
	@Path("search")
	public String postSearch(@FormParam("keyword") String keyword) {
		messagesDAO.search(keyword);
		// messages が @RedirectScoped なので、リダイレクト先でも参照可能。
		return "redirect:list";
	}

	@GET
	@Path("users")
	public String getUsers() {
		usersDAO.getAll();
		return "users.jsp";
	}

	@POST
	@Path("users")
	public String createUsers(@BeanParam UserDTO user) {
		var hash = passwordHash.generate(user.getPassword().toCharArray());
		user.setPassword(hash);
		usersDAO.create(user);

		return "redirect:users";
	}

	@POST
	@Path("user_delete")
	public String deleteUser(@FormParam("name") String name) {
		usersDAO.delete(name);
		return "redirect:users";
	}

	@POST
	@Path("user_update")
	public String updateUser(@BeanParam UserDTO user) {
		var hash = passwordHash.generate(user.getPassword().toCharArray());
		user.setPassword(hash);
		usersDAO.update(user);
		return "redirect:users";
	}

}
