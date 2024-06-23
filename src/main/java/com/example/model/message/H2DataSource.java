package com.example.model.message;

import javax.sql.DataSource;

import jakarta.annotation.Resource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

/*
 * MessagesDAOクラスが使用するDataSourceを提供するクラスです。
 * 今回Payaraサーバ側でjdbc/__defaultに設定したH2データベースへ接続する機能を持ちます。
 */
@ApplicationScoped
public class H2DataSource {
	/**
	 * JNDIで管理されたDataSourceオブジェクトは@Resourceアノテーションで
	 * 注入できます。lookup属性でJNDI名を渡します。
	 * （簡単に書けますが、コンストラクタインジェクションできないので使いにくい面もあります。）
	 */
	@Resource(lookup = "jdbc/__default")
	private DataSource ds;

	/*
	 * @Producesアノテーションのついたメソッドは、CDIのプロデューサメソッドです。
	 * このメソッドは、DataSource型のインジェクションポイントにマッチすることができ、
	 * 戻り値のdsオブジェクトを注入します。
	 * （プロデューサメソッドはデータ型が重要であってメソッド名は任意です。）
	 */
	@Produces
	public DataSource getDataSource() {
		return ds;
	}
}
