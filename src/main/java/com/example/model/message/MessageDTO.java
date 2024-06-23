package com.example.model.message;

import jakarta.ws.rs.FormParam;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * メッセージ情報の受け渡しに用いるDTO（Data Transfer Object）です。
 *
 * MessageDAOクラスでは、このMessageDTOのインスタンスを作りたいので、
 * @AllArgsConstructor で全フィールドを引数にもつコンストラクタを追加。
 * 
 * @BeanParam を用いて注入する際にはデフォルトコンストラクタも必要なため、
 * @NoArgsConstructor が必要です。
 * 
 * @BeanParam でデータを渡すためには
 * list.jspのフォーム内でのinput要素のnameと
 * クラスのフィールドとの対応付けを
 * @FormParam で指定しておく必要があります。
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
public class MessageDTO {
	@FormParam("id")
	private int id;
	@FormParam("name")
	private String name;
	@FormParam("message")
	private String message;
}