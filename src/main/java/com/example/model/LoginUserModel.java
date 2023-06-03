package com.example.model;

import java.io.Serializable;

import jakarta.enterprise.context.SessionScoped;
import jakarta.inject.Named;
import lombok.Data;

/**
 * LoginUserModelはログインユーザの情報を保持するクラスです。
 */

@SessionScoped
@Named
@Data
public class LoginUserModel implements Serializable {
	private String name = null;
}

