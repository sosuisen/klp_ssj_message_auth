package com.example.model.message;

import java.util.ArrayList;

import jakarta.inject.Named;
import jakarta.mvc.RedirectScoped;

/**
 * MyControllerからJSPへのデータ受け渡しを担います。
 * リダイレクト後のページで用いることがあるので @RedirectScoped とします。
 */
@RedirectScoped
@Named
public class MessagesModel extends ArrayList<MessageDTO> {
}
