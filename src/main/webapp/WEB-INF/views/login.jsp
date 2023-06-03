<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="${mvc.basePath}/../app.css" rel="stylesheet">
<title>メッセージアプリ：ログイン</title>
</head>
<body>
	[<a href="${mvc.basePath}/">ホーム</a>]
	<hr>
	<form action="${mvc.basePath}/login" method="POST">
		ユーザ名：<input type="text" name="name"><br> パスワード：<input
			type="password" name="password">
		<button>ログイン</button>
	</form>
	<p style="color: green">
		<c:forEach var="msg" items="${ messages }"> 
			<c:if test="${ msg == 'logout' }">ログアウトしました。<br></c:if>
		</c:forEach>
	</p>
	<p style="color: red">
		<c:forEach var="err" items="${ errors }"> 
			<c:if test="${ err == 'invalid_user' }">ユーザ名もしくはパスワードが異なります。<br></c:if>
			<c:if test="${ err == 'forbidden' }">このアカウントでは権限のない操作です。<br></c:if>			
		</c:forEach>
	</p>
</body>
</html>
