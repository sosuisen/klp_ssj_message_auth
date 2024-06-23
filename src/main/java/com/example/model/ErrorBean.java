package com.example.model;

import java.io.Serializable;

import jakarta.inject.Named;
import jakarta.mvc.RedirectScoped;
import lombok.Data;

@RedirectScoped
@Named
@Data
public class ErrorBean implements Serializable {
	private String message;
}
