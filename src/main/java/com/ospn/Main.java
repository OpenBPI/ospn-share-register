package com.ospn;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class Main {
    public static byte[] sha256(byte[] data){
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(data);
            data = messageDigest.digest();
        } catch (Exception e){
            e.printStackTrace();
        }
        return data;
    }
    public static String aesEncrypt(String data, String key){
        try {
            byte[] iv = new byte[16];
            Arrays.fill(iv,(byte)0);
            byte[] pwdHash = sha256(key.getBytes());
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(pwdHash, "AES"), new IvParameterSpec(iv));
            byte[] encData = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encData);
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    public static String aesDecrypt(String data, String key){
        try {
            byte[] iv = new byte[16];
            Arrays.fill(iv,(byte)0);
            byte[] rawData = Base64.getDecoder().decode(data);
            byte[] pwdHash = sha256(key.getBytes());
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(pwdHash, "AES"), new IvParameterSpec(iv));
            rawData = cipher.doFinal(rawData);
            return new String(rawData);
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    public static void main(String[] args) {
        try {
            if(args.length != 4){
                System.out.println("host username password adminkey");
                return;
            }
            URL url = new URL("http://"+args[0]+"/admin");
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setConnectTimeout(5000);
            httpURLConnection.setReadTimeout(5000);
            httpURLConnection.setDoInput(true);
            httpURLConnection.setDoOutput(true);
            JSONObject json = new JSONObject();
            json.put("username", args[1]);
            json.put("password", args[2]);
            String body = aesEncrypt(json.toString(), args[3]);
            json.clear();
            json.put("command", "register");
            json.put("data", body);
            OutputStream outputStream = httpURLConnection.getOutputStream();
            outputStream.write(json.toString().getBytes());
            outputStream.flush();
            outputStream.close();

            if(httpURLConnection.getResponseCode() == 200){
                InputStream responseStream = httpURLConnection.getInputStream();
                ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int bytesRead = 0;
                while ((bytesRead = responseStream.read(buffer)) > 0) {
                    byteStream.write(buffer, 0, bytesRead);
                }
                String responseBody = byteStream.toString("utf-8");
                System.out.println(responseBody);
                json = JSON.parseObject(responseBody);
                body = json.getString("data");
                if(body != null){
                    body = aesDecrypt(body, args[3]);
                    System.out.println(body);
                }
            } else {
                System.out.println("error: "+httpURLConnection.getResponseCode());
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
