package com.cloudpos.apps.tester;


import android.app.Activity;
import android.os.Handler;
import android.os.Message;
import android.widget.TextView;

import com.cloudpos.utils.Logger;

public abstract class AbstractActivity extends Activity {


    protected TextView log_text;
    protected static Handler mHandler = null;

    public static void writerInLog(String obj, int id) {
        if (mHandler != null) {
            Message msg = new Message();
            msg.what = id;
            msg.obj = obj;
            mHandler.sendMessage(msg);
        }
    }

    public static void writerInSuccessLog(String obj) {
        Logger.debug(obj);
        writerInLog(obj, R.id.log_success);
    }

    public static void writerInFailedLog(String obj) {
        writerInLog(obj, R.id.log_failed);
    }

    public static void clear() {

        writerInLog("", R.id.log_clear);
    }

}
