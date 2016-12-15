package net.kibotu.openssl.jni;

import android.support.annotation.IntRange;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.util.Random;
import java.util.concurrent.TimeUnit;


/**
 * Created by <a href="https://about.me/janrabe">Jan Rabe</a>.
 */

public class NativeOpenSSL {

    private static final String TAG = NativeOpenSSL.class.getSimpleName();

    /**
     * Used to load the 'native-lib' library on application startup.
     */
    static {
        System.loadLibrary("opensslwrapper");
    }

    public native void init();

    public native byte[] encrypt(byte[] password, byte[] message);

    public native byte[] decrypt(byte[] password, byte[] message);

    public static class AESEncrypt {

        public String data;
        public long time;

        public AESEncrypt setData(String data) {
            this.data = data;
            return this;
        }

        public AESEncrypt setTime(long time) {
            this.time = time;
            return this;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            AESEncrypt that = (AESEncrypt) o;

            if (time != that.time) return false;
            return data != null ? data.equals(that.data) : that.data == null;

        }

        @Override
        public int hashCode() {
            int result = data != null ? data.hashCode() : 0;
            result = 31 * result + (int) (time ^ (time >>> 32));
            return result;
        }

        @Override
        public String toString() {
            return "AESEncrypt{" +
                    "data='" + data + '\'' +
                    ", time=" + time +
                    '}';
        }

        public boolean timedOut(int units, TimeUnit unit) {
            return NativeOpenSSL.timedOut(nowInSeconds(), time, units, unit);
        }
    }

    public static class AESDecrypt {

        public String data;
        public long time;

        public AESDecrypt setDecrypted(String decrypted) {
            this.data = decrypted;
            return this;
        }

        public AESDecrypt setTime(long time) {
            this.time = time;
            return this;
        }

        public boolean timedOut(int units, TimeUnit unit) {
            return NativeOpenSSL.timedOut(nowInSeconds(), time, units, unit);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            AESDecrypt that = (AESDecrypt) o;

            if (time != that.time) return false;
            return data != null ? data.equals(that.data) : that.data == null;

        }

        @Override
        public int hashCode() {
            int result = data != null ? data.hashCode() : 0;
            result = 31 * result + (int) (time ^ (time >>> 32));
            return result;
        }

        @Override
        public String toString() {
            return "AESDecrypt{" +
                    "data='" + data + '\'' +
                    ", time=" + time +
                    '}';
        }
    }

    /**
     * <p>
     * Encrypt Data
     * <p>
     * To encrypt data, the following steps need to be performed:
     * <p>
     * 1. Extract the 16 byte password from your secure storage. (Assuming the password has been created already).
     * 2. Convert the JSON plain text to be encrypted to Latin1 and store it in a byte array.
     * 3. Append a 0x00 to the end of the byte array. This is very import and since it delimits the payload string.
     * 4. Add four random ASCII chars to the beginning of the byte array (Its important that the first four bytes are non zero). Make sure you seed your random generator properly and generate new four random chars for every message you are going to encrypt.
     * 5. Depending on your AES implementation, it might be necessary to pad the byte array until length mod 16 == 0 is true. Padding bytes can be just 0x00, but other padding content might work as well. Byte array content before encryption (example)
     * <p>
     * <image src="http://i.imgur.com/iS1spsf.png" />
     * <p>
     * 6. Set the 16 byte password for your AES library. Use the 16 byte password for the initialisation vector too.
     * 7. Encrypt the data.
     * 8. Convert the encrypted to base64 to get a string. Surround the base64 string of the encrypted data by square brackets and double quotes to have a valid JSON. Depending of your PubNub client, it might be not necessary to add square brackets.
     * 9. Send the data.
     * <p>
     * <image src="http://i.imgur.com/2v8kNR9.png" />
     * </pre>
     * <p>
     * Example
     * <pre>
     * Plain Text:
     * "{"cmd":{"dev":"info"}}\n"
     *
     * Key and IV:
     * 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
     *
     * Input String:
     * 30 31 30 32 7b 22 63 6d 64 22 3a 7b 22 64 65 76
     * 22 3a 22 69 6e 66 6f 22 7d 7d 0a
     *
     * Delimited and Padded String:
     * 30 31 30 32 7b 22 63 6d 64 22 3a 7b 22 64 65 76
     * 22 3a 22 69 6e 66 6f 22 7d 7d 0a 00 00 00 00 00
     *
     * Encrypted String:
     * 0f 47 f7 11 53 a2 ae ff 30 c8 16 01 b6 99 3d ba
     * 71 fa 00 f2 f4 af 08 19 8f 80 01 fa 3f 45 39 e1
     *
     * Base64 Encoded String:
     * "D0f3EVOirv8wyBYBtpk9unH6APL0rwgZj4AB+j9FOeE=" // in my case, I do not need to add square brackets
     *
     * URL =  QUrl("https://pubsub.pubnub.com/publish/pub-c-2a5ee022-4e83-4f8e-a37c-4e44b8470929/sub-c-95b2b6b8-ec74-11e5-be6a-02ee2ddab7fe/0/cc47a957-eade-4986-8898-68607c8d0d11-in/0/%22D0f3EVOirv8wyBYBtpk9unH6APL0rwgZj4AB%2Bj9FOeE=%22?pnsdk=Qt5%2F2.1.0&uuid=DESKTOP-SLR2S53-app?store=false")
     * </pre>
     *
     * @param json Message
     * @return Encrypted message
     */
    @Deprecated
    public String encryptV1(byte[] password, String json) {
        return Base64.encodeToString(encrypt(password, addLeadingBytesAndPadding(json)), Base64.NO_WRAP);
    }

    public AESEncrypt encrypt(byte[] password, String json) {
        Pair<byte[], Long> pair = addLeadingBytesAndPaddingWithTime(json);
        return new AESEncrypt()
                .setData(Base64.encodeToString(encrypt(password, pair.first), Base64.NO_WRAP))
                .setTime(pair.second);
    }

    /**
     * Decrypt Data
     * <p>
     * <p>
     * Decrypting data works vice versa to encryption:
     * <p>
     * Remove the square brackets and the double quotes or use a JSON parser and take the first element of the JSON array.
     * Decode the base64 string. It might be good to limit the max accepted length. Otherwise large, faulty messages could block the decoding App or crash it.
     * Use the 16 byte password as key and initialisation vector for your AES decryption function.
     * Decrypt the data.
     * Remove the leading four bytes.
     * Remove the padding data (and the limiter) to get the payload string
     * <p>
     * <p>
     * Example:
     * <pre>
     *     Base64 Input String (Brackets and quotes are already removed here):  Exzx+rE8tItMEgrfhYHhVHvIP3m43dqBrfYAxAvwoUtvocWHGKtvR4ysFvtKjjJx6KgUZcRSjjv5wKLgTf4A2yNOSqmC6dM0ew5+6g4+I2V0HGzJIRI8FqXHTGI8VN/eIXBc6b3p8LLMFxetPlmufXwNx6fLsNfW4Nu6LqvAtTV6mhbN2Rn+OcsO+fRgFdkPthz0V8R43E/q/hMsNzF/EyKchGwTSpb6r75Irv8G7j+i3TR60gh5ntJ8Yt0WHnWkifT/bky9IpdcnS/aijJQ5HVeiZHpU6+DrhJOWEhfHQzTMrGtHScpNG3ngcf9TPkfWx3VfCyHYEnFEZgJPVDwJ7mXloamxhc6AHag4YdYuc8RoId1G1z+lMVjrwzh14AY66XoaZxFxIHCldc849tQbGWBFnuL8MEWfUOi0wyDAWUwTIotRQ+bXTlYPZy1gQ9L
     *
     *
     * Base64 Decoded String:
     * 13 1c f1 fa b1 3c b4 8b 4c 12 0a df 85 81 e1 54
     * 7b c8 3f 79 b8 dd da 81 ad f6 00 c4 0b f0 a1 4b
     * 6f a1 c5 87 18 ab 6f 47 8c ac 16 fb 4a 8e 32 71
     * e8 a8 14 65 c4 52 8e 3b f9 c0 a2 e0 4d fe 00 db
     * 23 4e 4a a9 82 e9 d3 34 7b 0e 7e ea 0e 3e 23 65
     * 74 1c 6c c9 21 12 3c 16 a5 c7 4c 62 3c 54 df de
     * 21 70 5c e9 bd e9 f0 b2 cc 17 17 ad 3e 59 ae 7d
     * 7c 0d c7 a7 cb b0 d7 d6 e0 db ba 2e ab c0 b5 35
     * 7a 9a 16 cd d9 19 fe 39 cb 0e f9 f4 60 15 d9 0f
     * b6 1c f4 57 c4 78 dc 4f ea fe 13 2c 37 31 7f 13
     * 22 9c 84 6c 13 4a 96 fa af be 48 ae ff 06 ee 3f
     * a2 dd 34 7a d2 08 79 9e d2 7c 62 dd 16 1e 75 a4
     * 89 f4 ff 6e 4c bd 22 97 5c 9d 2f da 8a 32 50 e4
     * 75 5e 89 91 e9 53 af 83 ae 12 4e 58 48 5f 1d 0c
     * d3 32 b1 ad 1d 27 29 34 6d e7 81 c7 fd 4c f9 1f
     * 5b 1d d5 7c 2c 87 60 49 c5 11 98 09 3d 50 f0 27
     * b9 97 96 86 a6 c6 17 3a 00 76 a0 e1 87 58 b9 cf
     * 11 a0 87 75 1b 5c fe 94 c5 63 af 0c e1 d7 80 18
     * eb a5 e8 69 9c 45 c4 81 c2 95 d7 3c e3 db 50 6c
     * 65 81 16 7b 8b f0 c1 16 7d 43 a2 d3 0c 83 01 65
     * 30 4c 8a 2d 45 0f 9b 5d 39 58 3d 9c b5 81 0f 4b
     *
     *
     * Decrypted Data:
     * 34 36 34 33 7b 22 69 6e 66 6f 22 3a 7b 22 63 76
     * 65 72 73 22 3a 22 31 22 2c 22 76 65 72 73 22 3a
     * 22 6c 32 62 2d 31 2e 33 2e 30 2d 32 30 31 36 31
     * 31 31 35 2e 32 31 31 37 31 33 22 2c 22 64 6e 22
     * 3a 22 56 47 39 79 63 33 52 6c 62 69 42 4d 4d 6b
     * 49 3d 22 2c 22 67 6e 22 3a 22 56 47 56 7a 64 47
     * 64 79 64 58 42 77 5a 51 3d 3d 22 2c 22 64 63 6e
     * 22 3a 22 65 65 66 39 63 37 33 63 2d 32 31 38 38
     * 2d 34 64 30 38 2d 38 61 30 38 2d 65 66 30 35 35
     * 64 32 34 35 63 36 35 22 2c 22 68 74 72 22 3a 22
     * 6f 66 66 22 2c 22 6d 64 65 22 3a 22 6d 61 6e 75
     * 61 6c 22 2c 22 65 6f 6c 22 3a 22 31 30 30 22 2c
     * 22 73 73 63 74 73 22 3a 22 32 30 31 36 31 31 31
     * 35 32 31 34 34 33 34 22 2c 22 61 6e 73 22 3a 22
     * 31 32 33 34 35 36 37 38 39 30 22 2c 22 73 63 68
     * 65 64 22 3a 5b 7b 22 73 65 74 22 3a 22 73 22 2c
     * 22 65 6e 22 3a 22 31 22 2c 22 68 74 72 22 3a 22
     * 74 65 6d 70 31 22 2c 22 77 64 70 22 3a 22 31 32
     * 37 22 2c 22 73 74 73 22 3a 22 31 32 30 30 22 2c
     * 22 64 75 72 22 3a 22 36 30 30 22 7d 5d 7d 7d 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     *
     *
     * Final string:
     * {"info":{"cvers":"1","vers":"l2b-1.3.0-20161115.211713","dn":"VG9yc3RlbiBMMkI=","gn":"VGVzdGdydXBwZQ==","dcn":"eef9c73c-2188-4d08-8a08-ef055d245c65","htr":"off","mde":"manual","eol":"100","sscts":"20161115214434","ans":"1234567890","sched":[{"set":"s","en":"1","htr":"temp1","wdp":"127","sts":"1200","dur":"600"}]}}
     *
     * </pre>
     *
     * @param message Encrypted Message.
     * @return Json Message
     */
    @Deprecated
    public String decryptV1(byte[] password, String message) {
        return removeLeadingBytesAndPadding(decrypt(password, Base64.decode(message.getBytes(), Base64.NO_WRAP)));
    }

    public AESDecrypt decrypt(byte[] password, AESEncrypt message) {
        return decrypt(password, message.data);
    }

    public AESDecrypt decrypt(byte[] password, String message) {
        return removeLeadingBytesAndPaddingWithTime(decrypt(password, Base64.decode(message.getBytes(), Base64.NO_WRAP)));
    }

    /**
     * <img src="http://i.imgur.com/hHBTnro.png" />
     */
    private Pair<byte[], Long> addLeadingBytesAndPaddingWithTime(String plainMessage) {

        int terminationBytes = 1;
        int randomBytes = 8;

        // 1) 8 bytes random (must be non zero)
        byte[] nonZeroRandomBytes = randomNonZeroBytes(randomBytes);

        // 2) 8 bytes epoch time
        long seconds = nowInSeconds();
        byte[] epochTimeBytes = asEpochSeconds(seconds);

        // 3) n bytes plain message
        byte[] plainBytes = plainMessage.getBytes();

        // create final byte array
        byte[] finalByteMessage = new byte[plainBytes.length + randomBytes + epochTimeBytes.length + terminationBytes];

        // set first 8 bytes non zero random bytes
        System.arraycopy(nonZeroRandomBytes, 0, finalByteMessage, 0, nonZeroRandomBytes.length);

        // set first 8 bytes non zero random bytes
        System.arraycopy(epochTimeBytes, 0, finalByteMessage, nonZeroRandomBytes.length, epochTimeBytes.length);

        // copy actual message bytes
        System.arraycopy(plainBytes, 0, finalByteMessage, nonZeroRandomBytes.length + epochTimeBytes.length, plainBytes.length);

        // 4) 1 byte termination '0x00'
        finalByteMessage[finalByteMessage.length - 1] = 0x00;

        return new Pair<>(finalByteMessage, seconds);
    }

    private byte[] addLeadingBytesAndPadding(String plainMessage) {

        int terminationBytes = 1;
        int randomBytes = 4;

        // plain message to bytes
        byte[] plainBytes = plainMessage.getBytes();

        // create final byte array
        byte[] finalByteMessage = new byte[plainBytes.length + randomBytes + terminationBytes];

        // create 4 random non zero bytes
        byte[] nonZeroBytes = randomNonZeroBytes(randomBytes);

        // set first 4 bytes non zero random bytes
        System.arraycopy(nonZeroBytes, 0, finalByteMessage, 0, nonZeroBytes.length);

        // copy actual message bytes
        System.arraycopy(plainBytes, 0, finalByteMessage, nonZeroBytes.length, plainBytes.length);

        // set last byte '0x00' termination
        finalByteMessage[finalByteMessage.length - 1] = 0x00;

        return finalByteMessage;
    }

    private String removeLeadingBytesAndPadding(byte[] decryptedMessage) {

        int randomBytes = 4;

        int lastIndex = randomBytes;

        // find index of '0x00' termination byte
        for (int i = randomBytes; i < decryptedMessage.length; ++i)
            if (decryptedMessage[i] == 0x00) {
                lastIndex = i;
                break;
            }

        // create message
        byte[] message = new byte[lastIndex - randomBytes];

        // copy actual message into return value
        System.arraycopy(decryptedMessage, randomBytes, message, 0, lastIndex - randomBytes);

        return new String(message);
    }

    private AESDecrypt removeLeadingBytesAndPaddingWithTime(byte[] decryptedMessage) {

        int randomBytes = 8;
        int amountEpochTimeBytes = 8;

        int lastIndex = randomBytes + amountEpochTimeBytes;

        // find index of '0x00' termination byte
        for (int i = randomBytes; i < decryptedMessage.length; ++i)
            if (decryptedMessage[i] == 0x00) {
                lastIndex = i;
                break;
            }

        byte[] epochBytes = new byte[amountEpochTimeBytes];

        System.arraycopy(decryptedMessage, randomBytes, epochBytes, 0, epochBytes.length);

        // create message
        byte[] message = new byte[lastIndex - (randomBytes + amountEpochTimeBytes)];

        // copy actual message into return value
        System.arraycopy(decryptedMessage, randomBytes + amountEpochTimeBytes, message, 0, lastIndex - (randomBytes + amountEpochTimeBytes));

        return new AESDecrypt()
                .setDecrypted(new String(message))
                .setTime(epochBytesToSeconds(epochBytes));
    }

    public static boolean timedOut(long start, long end, int units, TimeUnit unit) {
        return Math.abs(start - end) >= unit.toSeconds(units);
    }

    public static long epochBytesToSeconds(byte[] epochBytes) {
        return Long.valueOf(new String(epochBytes), 16);
    }

    public static byte[] asEpochSeconds(long seconds) {
        return Long.toHexString(seconds).getBytes();
    }

    public static long nowInSeconds() {
        return new DateTime(DateTimeZone.UTC).getMillisOfSecond() / 1000L;
    }

    public static byte[] randomNonZeroBytes(int count) {
        return randomBytesInRange(count, 1, 254);
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] randomBytesInRange(int count, @IntRange(from = 0, to = 255) int start, @IntRange(from = 0, to = 255) int end) {
        final Random random = new Random();
        final byte[] bytes = new byte[count];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (random.nextInt(end) + start);
        }
        return bytes;
    }

    public static byte[] fromHexString(final String encoded) {
        if ((encoded.length() % 2) != 0)
            throw new IllegalArgumentException("Input string must contain an even number of characters");

        final byte result[] = new byte[encoded.length() / 2];
        final char enc[] = encoded.toCharArray();
        for (int i = 0; i < enc.length; i += 2) {
            result[i / 2] = (byte) Integer.parseInt(String.valueOf(enc[i]) + enc[i + 1], 16);
        }
        return result;
    }


    public static void encryptDecryptTest() {

        NativeOpenSSL nativeOpenSSL = new NativeOpenSSL();
        nativeOpenSSL.init();

        byte[] cipher = fromHexString("00112233445566778899AABBCCDDEEFF");
        String json = "리필 리셋";
        Log.v(TAG, "[jni] cipher= " + bytesToHex(cipher) + " message=" + json);

        String encrypt = nativeOpenSSL.encryptV1(cipher, json);
        Log.v(TAG, "[jni] encrypted= " + encrypt);
        Log.v(TAG, "[jni] decrypted= " + nativeOpenSSL.decryptV1(cipher, encrypt));

        AESEncrypt result = nativeOpenSSL.encrypt(cipher, json);
        Log.v(TAG, "[jni] encryptWithTime= " + result);
        final AESDecrypt decrypt = nativeOpenSSL.decrypt(cipher, result);


        Log.v(TAG, "[jni] wait");
        try {
            Thread.sleep(4000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Log.v(TAG, "[jni] continue");
        Log.v(TAG, "[jni] decrypted= " + decrypt + " timedOut (61s+) =" + decrypt.timedOut(5, TimeUnit.SECONDS));


        Log.v(TAG, "[jni] wait");
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Log.v(TAG, "[jni] continue");
        Log.v(TAG, "[jni] decrypted= " + decrypt + " timedOut (61s+) =" + decrypt.timedOut(5, TimeUnit.SECONDS));
    }
}
