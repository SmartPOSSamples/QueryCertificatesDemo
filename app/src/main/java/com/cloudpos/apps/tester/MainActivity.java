package com.cloudpos.apps.tester;


import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.text.method.ScrollingMovementMethod;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

import com.alibaba.fastjson.JSONObject;
import com.cloudpos.DeviceException;
import com.cloudpos.POSTerminal;
import com.cloudpos.hsm.HSMDevice;
import com.cloudpos.utils.TextViewUtil;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;



public class MainActivity extends AbstractActivity implements OnClickListener {

    private HSMDevice device;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        device = (HSMDevice) POSTerminal.getInstance(this)
                .getDevice("cloudpos.device.hsm");

        setContentView(R.layout.activity_main);

        Button btn_test1 = (Button) this.findViewById(R.id.btn_test1);
        Button btn_test2 = (Button) this.findViewById(R.id.btn_test2);
        Button btn_test3 = (Button) this.findViewById(R.id.btn_test3);

        log_text = (TextView) this.findViewById(R.id.text_result);
        log_text.setMovementMethod(ScrollingMovementMethod.getInstance());

        findViewById(R.id.settings).setOnClickListener(this);
        btn_test1.setOnClickListener(this);
        btn_test2.setOnClickListener(this);
        btn_test3.setOnClickListener(this);

        mHandler = new Handler() {
            @Override
            public void handleMessage(Message msg) {
                if (msg.what == R.id.log_default) {
                    log_text.append("\t" + msg.obj + "\n");
                } else if (msg.what == R.id.log_success) {
                    String str = "\t" + msg.obj + "\n";
                    TextViewUtil.infoBlueTextView(log_text, str);
                } else if (msg.what == R.id.log_failed) {
                    String str = "\t" + msg.obj + "\n";
                    TextViewUtil.infoRedTextView(log_text, str);
                } else if (msg.what == R.id.log_clear) {
                    log_text.setText("");
                }
            }
        };
    }

    @Override
    public void onClick(View arg0) {
        int index = arg0.getId();
        if (index == R.id.btn_test1) {
            open();
        } else if (index == R.id.btn_test2) {
            queryCertificates();
        } else if (index == R.id.btn_test3) {
            close();
        } else if (index == R.id.settings) {
            log_text.setText("");
        }
    }

    public void open() {
        try {
            device.open();
            writerInSuccessLog("\n open succeed!");
        } catch (DeviceException e) {
            e.printStackTrace();
            writerInFailedLog("\n open failed!");
        }
    }

    public void queryCertificates() {
        try {
            final String[] alias = device.queryCertificates(HSMDevice.CERT_TYPE_PUBLIC_KEY);
            if (alias!=null){
                for (int i = 0; i < alias.length; i++) {
                    byte[] buf = device.getCertificate(HSMDevice.CERT_TYPE_PUBLIC_KEY,alias[i],HSMDevice.CERT_FORMAT_PEM);
                    Log.d("PUBLIC :"+alias[i],convertToPem(byteArrayToX509Certificate(buf)));
                }
            }
            final String[] aliasowner = device.queryCertificates(HSMDevice.CERT_TYPE_TERMINAL_OWNER);
            if (aliasowner!=null){
                for (int i = 0; i < aliasowner.length; i++ ){
                    byte[] buf = device.getCertificate(HSMDevice.CERT_TYPE_TERMINAL_OWNER,aliasowner[i],HSMDevice.CERT_FORMAT_PEM);
                    Log.d("TERMINAL :"+aliasowner[i],convertToPem(byteArrayToX509Certificate(buf)));
                }
            }
            final String[] aliascomm = device.queryCertificates(HSMDevice.CERT_TYPE_COMM_ROOT);
            if (aliascomm!=null){
                for (int i = 0; i < aliascomm.length; i++ ){
                    byte[] buf = device.getCertificate(HSMDevice.CERT_TYPE_COMM_ROOT,aliascomm[i],HSMDevice.CERT_FORMAT_PEM);
                    Log.d("COMMUNICATION :"+aliascomm[i],convertToPem(byteArrayToX509Certificate(buf)));
                }
            }
            final String[] aliaskeyloader = device.queryCertificates(HSMDevice.CERT_TYPE_KEYLOADER_ROOT);
            if (aliaskeyloader!=null){
                for (int i = 0; i < aliaskeyloader.length; i++ ){
                    byte[] buf = device.getCertificate(HSMDevice.CERT_TYPE_KEYLOADER_ROOT,aliaskeyloader[i],HSMDevice.CERT_FORMAT_PEM);
                    Log.d("KEYLOADER :"+aliaskeyloader[i],convertToPem(byteArrayToX509Certificate(buf)));
                }
            }
            writerInSuccessLog("\n public cert: " + Arrays.toString(alias) + "\n owner cert: " + Arrays.toString(aliasowner) + "\n keyloader cert: " + Arrays.toString(aliaskeyloader) + "\n comm cert: " + Arrays.toString(aliascomm));
        } catch (DeviceException e) {
            e.printStackTrace();
            writerInFailedLog("\n -QueryCertificates: failed! ");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate byteArrayToX509Certificate(byte[] certBytes) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (ByteArrayInputStream bais = new ByteArrayInputStream(certBytes)) {
            return (X509Certificate) certFactory.generateCertificate(bais);
        } catch (IOException e) {
            throw new CertificateException("Failed to convert byte array to X509Certificate", e);
        }
    }

    public static String convertToPem(X509Certificate certificate) throws IOException, CertificateEncodingException {
        byte[] certBytes = certificate.getEncoded();
        String base64Cert = Base64.encodeToString(certBytes, Base64.NO_WRAP);
        StringBuilder pemBuilder = new StringBuilder();
        pemBuilder.append(certificate);
        pemBuilder.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < base64Cert.length(); i += 64) {
            pemBuilder.append(base64Cert, i, Math.min(base64Cert.length(), i + 64)).append("\n");
        }
        pemBuilder.append("-----END CERTIFICATE-----\n");
        return pemBuilder.toString();
    }

    public void close() {
        try {
            device.close();
            writerInSuccessLog("\n close succeed!");
        } catch (DeviceException e) {
            e.printStackTrace();
            writerInFailedLog("\n close failed!");
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        close();
    }

}
