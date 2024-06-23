package com.example.controller;

import java.net.URI;
import java.util.logging.Level;

import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;

/*
 * 権限がないページへのアクセスは 403 Forbidden になるため、
 * 対応するExceptionMapperを追加
 */
@Provider
@RequiredArgsConstructor(onConstructor_ = @Inject)
@Log
public class ForbiddenExceptionMapper implements ExceptionMapper<ForbiddenException> {
	private final HttpServletRequest req;

	@Override
	public Response toResponse(ForbiddenException exception) {
		try {
			req.logout();
			req.getSession().invalidate();
		} catch (ServletException e) {
			log.log(Level.WARNING, "Failed to logout", e);
		}
		// ExceptionMapper内でのリダイレクト実行は Response.seeOther()
		return Response.seeOther(URI.create(req.getRequestURL().toString() + "?error=forbidden")).build();
	}
}
