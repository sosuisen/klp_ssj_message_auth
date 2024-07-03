package com.example.controller;

import java.sql.SQLException;
import java.util.logging.Level;

import com.example.auth.IdentityStoreConfig;
import com.example.model.user.UserDTO;
import com.example.model.user.UsersDAO;

import jakarta.annotation.PostConstruct;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;

/**
 * Jakarta MVCのコンロトーラクラスです。
 */
@Controller
@RequestScoped
@NoArgsConstructor(force = true)
@RequiredArgsConstructor(onConstructor_ = @Inject)
@Log
@RolesAllowed("ADMIN")
@Path("/")
public class UserController {
	private final Models models;
	private final UsersDAO usersDAO;
	private final Pbkdf2PasswordHash passwordHash;
	private final HttpServletRequest req;

	@PostConstruct
	public void afterInit() {
		passwordHash.initialize(IdentityStoreConfig.getHashParams());
		log.log(Level.INFO, "[user]%s, [ip]%s [url]%s".formatted(
				req.getRemoteUser(),
				req.getRemoteAddr(),
				req.getRequestURL().toString()));
	}
	
	@GET
	@Path("users")
	public String getUsers() throws SQLException {
		models.put("users", usersDAO.getAll());
		return "users.jsp";
	}

	@POST
	@Path("users")
	public String createUser(@BeanParam UserDTO user) throws SQLException {
		var hash = passwordHash.generate(user.getPassword().toCharArray());
		user.setPassword(hash);
		usersDAO.create(user);
		return "redirect:users";
	}

	@POST
	@Path("user_delete")
	public String deleteUser(@FormParam("name") String name) throws SQLException {
		usersDAO.delete(name);
		return "redirect:users";
	}

	@POST
	@Path("user_update")
	public String updateUser(@BeanParam UserDTO user) throws SQLException {
		if (!user.getPassword().equals("")) {
			var hash = passwordHash.generate(user.getPassword().toCharArray());
			user.setPassword(hash);
		}
		usersDAO.update(user);
		return "redirect:users";
	}
}
