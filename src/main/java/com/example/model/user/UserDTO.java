package com.example.model.user;

import jakarta.ws.rs.FormParam;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class UserDTO {
	@FormParam("name")
	private String name;
	@FormParam("role")
	private String role;
	@FormParam("password")
	private String password;
}

