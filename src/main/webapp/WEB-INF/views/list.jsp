<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="${mvc.basePath}/../app.css" rel="stylesheet">
<title>メッセージアプリ：メッセージ</title>
</head>
<body>
	[<a href="${mvc.basePath}/">ホーム</a>] [<a href="${mvc.basePath}/users">ユーザ管理</a>] [<a href="${mvc.basePath}/logout">ログアウト</a>]
	<hr>
	${ req.getRemoteUser() }${ req.isUserInRole("ADMIN") ? "[管理者]" : "" }さん、こんにちは！
	<form action="${mvc.basePath}/list" method="POST">
		メッセージ：<input type="text" name="message">
		<button>送信</button>
	</form>
	<form action="${mvc.basePath}/search" method="POST">
		検索語：<input type="text" name="keyword">
		<button>検索</button>
	</form>
	<form action="${mvc.basePath}/clear" method="GET">
		<button>Clear</button>
	</form>
	<hr>
	<h1>メッセージ一覧</h1>
	<c:forEach var="mes" items="${messages}">
		<div>${mes.name}:${mes.message}
	</c:forEach>
</body>
</html>
