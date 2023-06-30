package com.example.controller;

import com.example.auth.IdentityStoreConfig;
import com.example.model.user.UserDTO;
import com.example.model.user.UsersDAO;

import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.mvc.Controller;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;
import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import lombok.NoArgsConstructor;

@Controller
@RequestScoped
@NoArgsConstructor(force = true)
@RolesAllowed("ADMIN")
@Path("/")
public class UserController {

	private final UsersDAO usersDAO;

	private final Pbkdf2PasswordHash passwordHash;

	@Inject
	public UserController(UsersDAO usersDAO, Pbkdf2PasswordHash passwordHash) {
		this.usersDAO = usersDAO;
		this.passwordHash = passwordHash;
		passwordHash.initialize(IdentityStoreConfig.HASH_PARAMS);
	}

	@GET
	@Path("users")
	public String getUsers() {
		usersDAO.getAll();
		return "users.jsp";
	}

	@POST
	@Path("users")
	public String createUser(@BeanParam UserDTO user) {
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
		if (!user.getPassword().isEmpty()) {
			var hash = passwordHash.generate(user.getPassword().toCharArray());
			user.setPassword(hash);
		}
		usersDAO.update(user);
		return "redirect:users";
	}
}
