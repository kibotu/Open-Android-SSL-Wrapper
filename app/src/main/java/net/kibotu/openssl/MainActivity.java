package net.kibotu.openssl;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;

import net.kibotu.openssl.jni.NativeOpenSSL;

import yein.checksum.R;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // http://stackoverflow.com/questions/38832797/using-prebuilt-library-in-android-studio
        NativeOpenSSL.encryptDecryptTest(this);
    }
}
