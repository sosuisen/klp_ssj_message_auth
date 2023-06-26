package com.example.controller;

import java.net.URI;

import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/*
 * 権限がないページへのアクセスは 403 Forbidden になるため、
 * 対応するExceptionMapperを追加
 */
@Provider
public class ForbiddenExceptionMapper implements ExceptionMapper<ForbiddenException> {
	private HttpServletRequest req;

	@Inject
	public ForbiddenExceptionMapper(HttpServletRequest req) {
		this.req = req;
	}

	@Override
	public Response toResponse(ForbiddenException exception) {
		try {
			req.logout();
			req.getSession().invalidate();
		} catch (ServletException e) {
			e.printStackTrace();
		}
		// ExceptionMapper内でのリダイレクト実行は Response.seeOther()
		return Response.seeOther(URI.create(req.getRequestURL().toString() + "?error=forbidden")).build();
	}
}
