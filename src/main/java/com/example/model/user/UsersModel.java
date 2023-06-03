package com.example.model.user;

import java.util.ArrayList;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Named;


@Named
@RequestScoped
public class UsersModel extends ArrayList<UserDTO> {

}
