<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="${mvc.basePath}/../app.css" rel="stylesheet">
<title>メッセージアプリ：ユーザ管理</title>
<style>
.row_create {
	display: grid;
	grid-template-columns: 100px 100px 100px 50px;
}

.row {
	display: grid;
	grid-template-columns: 100px 100px 100px 50px 50px;
}
</style>
</head>
<body>
	[
	<a href="${mvc.basePath}/">ホーム</a>] [
	<a href="${mvc.basePath}/list">メッセージページ</a>] [
	<a href="${mvc.basePath}/logout">ログアウト</a>]
	<hr>
	<c:if test="${ req.isUserInRole('ADMIN') }">
		<span style="color: red;">${error}</span>
		<h1>新規ユーザ追加</h1>

		<form class="row_create" action="${mvc.basePath}/users" method="POST">
			<span>ユーザ名</span> <span>ロール</span> <span>パスワード</span> <span></span>
			<input type="text" name="name"> <input type="text" name="role"> 
			<input type="password" name="password">
			<button>追加</button>
		</form>
	</c:if>
	<hr>
	<h1>ユーザ一覧</h1>
	<div>
		<div class="row">
			<div>ユーザ名</div>
			<div>ロール</div>
			<div>パスワード</div>
		</div>

		<c:forEach var="user" items="${users}">
			<c:choose>
				<c:when test="${ req.isUserInRole('ADMIN') }">
					<form class="row" method="POST">
						<input type="hidden" name="name" value="${user.name}"> <span>${user.name}</span>
						<input type="text" name="role" value="${user.role}">
						<input type="password" name="password">
						<button formaction="${mvc.basePath}/user_update">更新</button>
						<button formaction="${mvc.basePath}/user_delete">削除</button>
					</form>
				</c:when>
				<c:otherwise>
					<div class="row">
						<span>${user.name}</span>
						<span>${user.role}</span>
					</div>
				</c:otherwise>
			</c:choose>
		</c:forEach>	
</body>
</html>
