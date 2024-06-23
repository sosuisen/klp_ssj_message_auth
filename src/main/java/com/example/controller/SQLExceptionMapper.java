package com.example.controller;

import java.sql.SQLException;
import java.util.logging.Level;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.java.Log;

@Provider
@Log
public class SQLExceptionMapper implements ExceptionMapper<SQLException> {
	@Override
	public Response toResponse(SQLException exception) {
		// ログにエラー内容を出力
		log.log(Level.SEVERE, "SQL Exception occurred", exception);
		// 500エラーを返す
		throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
		/*
		 * 独自のメッセージを表示したい場合は以下のようにする
		 * 
		return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity("Internal server error occurred")
				.build();
		}*/
	}
}
