<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
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
	<form action="j_security_check" method="POST">
		ユーザ名：<input type="text" name="j_username"><br>
		パスワード：<input type="password" name="j_password">
		<button>ログイン</button>
	</form>
	<p style="color: red">
		<c:choose>
			<c:when test="${ error == 'invalid_user' }">ユーザ名もしくはパスワードが異なります。<br></c:when>
			<c:when test="${ error == 'forbidden' }">このアカウントでは権限のない操作です。<br></c:when>			
		</c:choose>
	</p>
</body>
</html>
