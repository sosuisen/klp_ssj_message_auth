package com.example.controller;

import com.example.auth.IdentityStoreConfig;
import com.example.model.user.UserDTO;
import com.example.model.user.UsersDAO;

import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.mvc.Controller;
import jakarta.mvc.Models;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import lombok.NoArgsConstructor;

@Controller
@RequestScoped
@NoArgsConstructor(force = true)
@RolesAllowed({"ADMIN", "SUBADMIN"})
@Path("/")
public class UserController {

	private final Models models;
	
	private final UsersDAO usersDAO;

	private final Pbkdf2PasswordHash passwordHash;

	private final HttpServletRequest req;
	
	@Inject
	public UserController(Models models, UsersDAO usersDAO, Pbkdf2PasswordHash passwordHash, HttpServletRequest req) {
		this.models = models;
		this.usersDAO = usersDAO;
		this.passwordHash = passwordHash;
		passwordHash.initialize(IdentityStoreConfig.HASH_PARAMS);
		this.req = req;
	}

	@GET
	@Path("users")
	public String getUsers() {
		models.put("req", req);		
		usersDAO.getAll();
		return "users.jsp";
	}

	@POST
	@Path("users")
	@RolesAllowed("ADMIN")
	public String createUser(@BeanParam UserDTO user) {
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
}
