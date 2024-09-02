package com.cloudpos.utils;

import android.graphics.Color;
import android.text.Spannable;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.widget.TextView;

public class TextViewUtil {
	
	
	public static void infoColorfulTextView( TextView log_text, String msg ,int textColor){
		if(log_text.getText().length() > 256){
			log_text.setText("");
		}
		int start = 0;
		if (log_text.getText().length() == 0) {
		} else {
			start = log_text.getText().length();
		}
		log_text.append(msg);
		Spannable style = (Spannable) log_text.getText();
		int end = start + msg.length();
		ForegroundColorSpan color;
		color = new ForegroundColorSpan(textColor);
		style.setSpan(color, start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
	}
	
	
	public static void infoRedTextView( TextView log_text, String msg ){
		infoColorfulTextView(log_text, msg, Color.RED);
	}
	
	public static void infoBlueTextView( TextView log_text, String msg ){
		infoColorfulTextView(log_text, msg, Color.BLUE);
	}
	
	public static void infoMAGENTATextView( TextView log_text, String msg ){
		infoColorfulTextView(log_text, msg, Color.MAGENTA);
	}
	

}
