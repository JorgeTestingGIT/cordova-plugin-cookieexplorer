package com.siemens.mx.cookieexplorer;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;

import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

import android.os.Build;
import android.webkit.ValueCallback;
import android.webkit.CookieManager;
import android.util.Log;
import android.webkit.CookieSyncManager;
import android.security.KeyChain;


import org.apache.cordova.ICordovaCookieManager;
import org.xwalk.core.XWalkCookieManager;
import android.content.Context;
import android.content.SharedPreferences;

//Fragmentando
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.ICordovaClientCertRequest;
import org.apache.cordova.ICordovaCookieManager;
import org.apache.cordova.ICordovaHttpAuthHandler;
import org.apache.cordova.PluginResult;
import com.siemens.imc.ces.util.SaltCrypto;
import com.siemens.imc.ces.util.Utils;

import javax.crypto.KeyGenerator;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.security.KeyStore;
import android.util.Base64;
import javax.crypto.spec.GCMParameterSpec;
//import com.android.org.bouncycastle.jce.provider.BouncyCastleProvider;
//import com.android.org.bouncycastle.jce.provider.symmetric.AES;
import java.util.Calendar;
import android.security.KeyPairGeneratorSpec;
import java.security.KeyPairGeneratorSpi;
import 	java.math.BigInteger;
import 	javax.security.auth.x500.X500Principal;
import 	java.security.KeyPairGenerator;
import 	java.security.KeyPair;
import java.security.spec.AlgorithmParameterSpec;
import java.security.PublicKey;
import java.security.PrivateKey;
import 	javax.crypto.spec.IvParameterSpec;
import java.util.Enumeration;

public class CookieExplorer extends CordovaPlugin {

    public static final String ACTION_GET_COOKIE_VALUE = "getCookieValue";
    public static final String ACTION_SET_COOKIE_VALUE = "setCookieValue";
    public static final String ACTION_PREPARE_COOKIES_MANAGEMENT = "prepareCookieManagement";
    public static final String ACTION_CLEAR_MCOOKIE = "clearMCookie";
    public static final String ACTION_CLEAR_SESSIONCOOKIES = "clearSessionCookies";
    public static final String ACTION_GET_MCOOKIE = "getMCookie";
    public static final String ACTION_SET_MCOOKIE = "setMCookie";
    public static final String ALIAS = "tMCookie";

    private byte[] iv;
    private KeyStore keyStore;
    private String cookieStringNew;
    private byte[] encryption;

    @Override
    public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if (ACTION_GET_COOKIE_VALUE.equals(action)) {
            return this.getCookie(args, callbackContext);
        }
        else if (ACTION_SET_COOKIE_VALUE.equals(action)) {
            return this.setCookie(args, callbackContext);
        }
        else if (ACTION_PREPARE_COOKIES_MANAGEMENT.equals(action)) { 
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                //Log.i("CookieExplorer - ", "Elimina cookies normales");
                
                XWalkCookieManager cookieManager = new XWalkCookieManager();
                //Obtengo las cookies para el dominio de siemens.com
                String ckies = cookieManager.getCookie("https://.siemens.com");   
                String cookieValue = "";
                String cookieName = "AUTH_SESSION_ID";
                if(ckies != null)
                {
                    String[] cookies = ckies.split("; ");
                    Log.i("CookieExplorer - cuantas", Integer.toString(cookies.length));
                    for (int i = 0; i < cookies.length; i++) {
                        if (cookies[i].contains(cookieName + "=")) {
                            String cookieString = cookies[i];
                            String cookieDomain = ".siemens.com";
                            cookieString += "; Domain=" + cookieDomain;
                            cookieString += "; Expires=Wed, 31 Dec 2010 23:59:59 GMT";
                            cookieString += "; Path=" + "/";
                            Log.i("CookieExplorer - NEW COOKIE", cookieString);
                            cookieManager.setCookie(cookieDomain, cookieString);                            
                            cookieManager.setCookie("https://" + cookieDomain, cookieString);

                            cookieStringNew = cookies[i];
                            break;
                        }
                    }
                }

                //ELIMINAMOS UNO SI EXISTE
                try {

                    //GUARDAMOS LA INFORMACION
                    Context applicationContext = this.cordova.getActivity().getApplicationContext();
                    keyStore = KeyStore.getInstance("AndroidKeyStore");
                    keyStore.load(null);

                    Enumeration enumeration = keyStore.aliases();
                    while(enumeration.hasMoreElements()) {
                        String alias2 = (String)enumeration.nextElement();
                        Log.i("CookieExplorer - ", "existente " + alias2);
                    }
                    if(keyStore.containsAlias(ALIAS)) {
                        Log.i("CookieExplorer - ", "ya TIENE el alias " + ALIAS);
                        keyStore.deleteEntry(ALIAS);
                        Log.i("CookieExplorer - ", "SE ELIMINA el alias " + ALIAS);
                    }

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) 
                    {
                        //Log.i("CookieExplorer - ", "generamos p1");
                        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                        //Log.i("CookieExplorer - ", "generamos p1-1");
                        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_CBC).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7).build();
                        //Log.i("CookieExplorer - ", "generamos P1-2");
                        keyGenerator.init(keyGenParameterSpec);
                        SecretKey secretKey = keyGenerator.generateKey();
                        //Log.i("CookieExplorer - ", "generamos P1-3");
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                        //Log.i("CookieExplorer - ", "generamos P1-4");
                        iv = cipher.getIV();
                        encryption = cipher.doFinal(cookieStringNew.getBytes("UTF-8"));
                        SaltCrypto.setContext(applicationContext);
                        SharedPreferences prefs = Utils.getPreferences(applicationContext);
                        SharedPreferences.Editor spe = prefs.edit();
                        spe.remove("iv2");
                        spe.putString("iv2", Base64.encodeToString(iv, Base64.DEFAULT));
                        spe.commit();                       
                    }
                    else{
                        //Log.d("CookieExplorer - ", "generamos P2");
                        Calendar start = Calendar.getInstance();
                        Calendar end = Calendar.getInstance();
                        end.add(Calendar.YEAR, 1);
                        //Log.d("CookieExplorer - ", "generamos P2-2");
                        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                        //Log.d("CookieExplorer - ", "generamos P2-3");
                        AlgorithmParameterSpec spec;
                        spec =  new KeyPairGeneratorSpec.Builder(applicationContext)
                            .setAlias(ALIAS)
                            .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                            .setSerialNumber(BigInteger.ONE)
                            .setStartDate(start.getTime())
                            .setEndDate(end.getTime())
                            .build();
                        generator.initialize(spec);
                        //Log.d("CookieExplorer - ", "generamos P2-4");
                        KeyPair keyPair = generator.generateKeyPair();
                        //Log.d("CookieExplorer - ", "generamos P2-4.1" + keyPair.getPublic());
                        //Log.d("CookieExplorer - ", "generamos P2-4.2" + keyPair.getPrivate());

                        //Log.d("CookieExplorer - ", "generamos P2-5");
                        Cipher cipher = Cipher.getInstance("RSA");///ECB/NoPadding
                        //Log.d("CookieExplorer - ", "generamos P2-6");
                        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
                        iv = cipher.getIV();
                        int ivLen = (iv == null) ? 0 : iv.length;
                        //Log.d("CookieExplorer - ", "generamos P2-6.1" + Integer.toString(ivLen));
                        encryption = cipher.doFinal(cookieStringNew.getBytes("UTF-8"));
                        iv = cipher.getIV();
                        ivLen = (iv == null) ? 0 : iv.length;
                        //Log.d("CookieExplorer - ", "generamos P2-7" + Integer.toString(ivLen));

                        //SaltCrypto.setContext(applicationContext);
                        final SharedPreferences prefs = Utils.getPreferences(applicationContext);
                        //Log.d("CookieExplorer - ", "generamos P2-7.1");
                        final SharedPreferences.Editor spe = prefs.edit();
                        //Log.d("CookieExplorer - ", "generamos P2-7.2");
                        spe.remove("iv2");
                        //Log.d("CookieExplorer - ", "generamos P2-7.3");
                        spe.putString("iv2", Base64.encodeToString(iv, Base64.DEFAULT));
                        //Log.d("CookieExplorer - ", "generamos P2-7.4");
                        spe.commit();
                        //Log.d("CookieExplorer - ", "generamos P2-8 termino de meter en el shared");
                        
                        keyStore = KeyStore.getInstance("AndroidKeyStore");
                        keyStore.load(null);
                        //Log.d("CookieExplorer - ", "generamos P2-9");
                        final KeyStore.Entry secretKeyPairEntry = keyStore.getEntry(ALIAS, null);
                        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) secretKeyPairEntry).getPrivateKey();
                        //Log.d("CookieExplorer - ", "generamos P2-10");
                        PublicKey publicKey = keyStore.getCertificate(ALIAS).getPublicKey();
                        final Cipher cipher2 = Cipher.getInstance("RSA/ECB/NoPadding");
                        //Log.d("CookieExplorer - ", "generamos P2-11 termino de meter en el shared");
                        final GCMParameterSpec spec2 = new GCMParameterSpec(128, Base64.decode(iv, Base64.DEFAULT));
                        cipher2.init(Cipher.DECRYPT_MODE, privateKey, spec2);
                        final byte[] decodedData = cipher2.doFinal(encryption);
                        //Log.d("CookieExplorer - ", "generamos P2-12");
                        final String unencryptedString = new String(decodedData, "UTF-8");
                        //Log.d("CookieExplorer - DESEncriPTADA ", unencryptedString);
                    }    
                }
                catch(Exception e)
                {
                    //Log.d("CookieExplorer - ERROR ", e.getMessage());
                    Log.e("CookieExplorer - ERROR ", Log.getStackTraceString(e));
                    callbackContext.error(e.getMessage());
                }

                cookieManager.removeExpiredCookie();
                cookieManager.flushCookieStore();                
            }
            else {
                //Log.i("CookieExplorer - ", "Elimina cookies normales y de session");

                CookieSyncManager cookieSyncMngr = CookieSyncManager.getInstance();
                cookieSyncMngr.startSync();
                CookieManager cookieManager= CookieManager.getInstance();
                cookieManager.removeAllCookie();
                cookieManager.removeSessionCookie();
                cookieSyncMngr.stopSync();
                cookieSyncMngr.sync();
            }

            callbackContext.success();
        }
        else if (ACTION_SET_MCOOKIE.equals(action)){
            XWalkCookieManager cookieManager = new XWalkCookieManager();
            //Obtengo las cookies para el dominio de siemens.com
            String ckies = cookieManager.getCookie("https://.siemens.com");   
            String cookieValue = "";
            String cookieName = "AUTH_SESSION_ID";
            if(ckies == null)
            {
                try {
                    final SharedPreferences prefs = Utils.getPreferences(this.cordova.getActivity().getApplicationContext());
                    String cname = prefs.getString("CName", null);

                    keyStore = KeyStore.getInstance("AndroidKeyStore");
                    keyStore.load(null);
                    KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(ALIAS, null);
                    
                    if(secretKeyEntry != null) {
                        SecretKey secretKey2 = secretKeyEntry.getSecretKey();
                        Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS7Padding");
                        //OBtenemos el valor
                        SharedPreferences prefs2 = Utils.getPreferences(this.cordova.getActivity().getApplicationContext());
                        String iv2 = prefs2.getString("iv2", null);
                        //Log.i("CookieExplorer - SHARED ", iv2);
                        IvParameterSpec ivParamsSpec = new IvParameterSpec(Base64.decode(iv2, Base64.DEFAULT));
                        cipher2.init(Cipher.DECRYPT_MODE, secretKey2, ivParamsSpec);
                        byte[] decodedData = cipher2.doFinal(encryption);
                        String unencryptedString = new String(decodedData, "UTF-8");
                        //Log.i("CookieExplorer - DESEncriPTADA ", unencryptedString);

                        if (unencryptedString != "") {
                            String[] cookies = unencryptedString.split("=");
                            if (unencryptedString.contains(cookieName + "=")) {
                                String cookieString = unencryptedString;
                                String cookieDomain = ".siemens.com";
                                cookieString += "; Domain=" + cookieDomain;
                                cookieString += "; Expires=Wed, 31 Dec 2025 23:59:59 GMT";
                                cookieString += "; Path=" + "/";
                                //Log.i("CookieExplorer - NEW COOKIE", cookieString);
                                cookieManager.setCookie(cookieDomain, cookieString);                            
                                cookieManager.setCookie("https://" + cookieDomain, cookieString);
                                callbackContext.success();
                            }
                        }
                        else {
                            callbackContext.error("Cookie not found!");
                        }
                    }                                        
                }
                catch(Exception e) {
                    callbackContext.error("JSON parsing error");
                }
                
                return true;
            }
            else {
                callbackContext.success();
                return true;
            }
        }
        else if (ACTION_CLEAR_MCOOKIE.equals(action)){
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                XWalkCookieManager cookieManager = new XWalkCookieManager();
                //Obtengo las cookies para el dominio de siemens.com
                String ckies = cookieManager.getCookie("https://.siemens.com");   
                String cookieValue = "";
                String cookieName = "AUTH_SESSION_ID";
                if(ckies != null)
                {
                    String[] cookies = ckies.split("; ");
                    //Log.i("CookieExplorer - cuantas", Integer.toString(cookies.length));
                    for (int i = 0; i < cookies.length; i++) {
                        if (cookies[i].contains(cookieName + "=")) {
                            String cookieString = cookies[i];
                            String cookieDomain = ".siemens.com";
                            cookieString += "; Domain=" + cookieDomain;
                            cookieString += "; Expires=Wed, 31 Dec 2010 23:59:59 GMT";
                            cookieString += "; Path=" + "/";
                            //Log.i("CookieExplorer - NEW COOKIE", cookieString);
                            cookieManager.setCookie(cookieDomain, cookieString);                            
                            cookieManager.setCookie("https://" + cookieDomain, cookieString);

                            cookieStringNew = cookies[i];
                            break;
                        }
                    }
                }               

                cookieManager.removeExpiredCookie();
                cookieManager.flushCookieStore(); 
            }
            else {
                CookieSyncManager cookieSyncMngr = CookieSyncManager.getInstance();
                cookieSyncMngr.startSync();
                CookieManager cookieManager2= CookieManager.getInstance();
                //cookieManager2.removeAllCookie();
                cookieManager2.removeSessionCookie();
                cookieSyncMngr.stopSync();
                cookieSyncMngr.sync();
            }
            callbackContext.success();
        }
        else if(ACTION_GET_MCOOKIE.equals(action)){
            return this.getMCookie(args, callbackContext);            
        }
        else if (ACTION_CLEAR_SESSIONCOOKIES.equals(action)) {
            CookieManager cookieManager = CookieManager.getInstance();
            //Log.d("CookieExplorer - ", "entra a eliminar las cookies de las sessiones");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                cookieManager.removeSessionCookies(null);
                cookieManager.flush();
            }

            callbackContext.success();
        }       

        callbackContext.error("Invalid action");
        return false;

    }

    /**
     * returns cookie under given key
     * @param args
     * @param callbackContext
     * @return
     */
    private boolean getCookie(JSONArray args, final CallbackContext callbackContext) {
        try {
            final String url = args.getString(0);
            final String cookieName = args.getString(1);

            cordova
                    .getThreadPool()
                    .execute(new Runnable() {
                        public void run() {
                            try {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                                    
                                    //Log.d("CookieExplorer - Dominio", url);
                                    //Log.d("CookieExplorer - Nombre", cookieName);
                                    CookieManager cookieManager = CookieManager.getInstance();
                                    
                                    //if(cookieManager.hasCookies())
                                    //{
                                        //Log.d("CookieExplorer - ", "SI TIENE");
                                    //}
                                    //else
                                    //{
                                        //Log.d("CookieExplorer - ", "NO TIENE");
                                    //}
                                    
                                    String ckies = cookieManager.getCookie(url);                                    
                                    String cookieValue = "";
                                    if(ckies != null)
                                    {
                                        String[] cookies = ckies.split("; ");
                                        //Log.d("CookieExplorer - cuantas", Integer.toString(cookies.length));
                                        for (int i = 0; i < cookies.length; i++) {
                                            //Log.d("CookieExplorer - ", cookies[i].split("=")[0].trim());
                                            if (cookies[i].contains(cookieName + "=")) {
                                                cookieValue = cookies[i].split("=")[1].trim();
                                                break;
                                            }
                                        }
                                    }

                                    JSONObject json = null;

                                    if (cookieValue != "") {
                                        json = new JSONObject("{cookieValue:\"" + cookieValue + "\"}");
                                    }

                                    if (json != null) {
                                        PluginResult res = new PluginResult(PluginResult.Status.OK, json);
                                        callbackContext.sendPluginResult(res);
                                    }
                                    else {
                                        callbackContext.error("Cookie not found!");
                                    }
                                }
                                else {
                                    CookieSyncManager cookieSyncMngr=CookieSyncManager.getInstance();
                                    cookieSyncMngr.startSync();

                                    CookieManager cookieManager = CookieManager.getInstance();
                                    //if(cookieManager.hasCookies())
                                    //{
                                       // Log.d("CookieExplorer SYNC - ", "SI TIENE");
                                    //}
                                    //else
                                    //{
                                        //Log.d("CookieExplorer SYNC - ", "NO TIENE");
                                    //}
                                    String[] cookies = cookieManager.getCookie(url).split("; ");
                                    String cookieValue = "";

                                    //Log.d("CookieExplorer - cuantas", Integer.toString(cookies.length));
                                    for (int i = 0; i < cookies.length; i++) {
                                        //Log.d("CookieExplorer SYNC - ", cookies[i].split("=")[0].trim());
                                        if (cookies[i].contains(cookieName + "=")) {
                                            cookieValue = cookies[i].split("=")[1].trim();
                                            break;
                                        }
                                    }

                                    JSONObject json = null;

                                    if (cookieValue != "") {
                                        json = new JSONObject("{cookieValue:\"" + cookieValue + "\"}");
                                    }

                                    if (json != null) {
                                        PluginResult res = new PluginResult(PluginResult.Status.OK, json);
                                        callbackContext.sendPluginResult(res);
                                    }
                                    else {
                                        callbackContext.error("Cookie not found!");
                                    }

                                    cookieSyncMngr.stopSync();
                                    cookieSyncMngr.sync();
                                }
                            }
                            catch (Exception e) {
                                /*StringWriter sw = new StringWriter();
                                e.printStackTrace(new PrintWriter(sw));
                                Log.e("CookieExplorer - ERROR", sw.toString());*/
                                callbackContext.error(e.getMessage());
                            }
                        }
                    });

            return true;
        }
        catch(JSONException e) {
            callbackContext.error("JSON parsing error");
        }

        return false;
    }

    /**
     * sets cookie value under given key
     * @param args
     * @param callbackContext
     * @return boolean
     */
    private boolean setCookie(JSONArray args, final CallbackContext callbackContext) {
        try {
            final String url = args.getString(0);
            final String cookieName = args.getString(1);
            final String cookieValue = args.getString(2);

            cordova
                    .getThreadPool()
                    .execute(new Runnable() {
                        public void run() {
                            try {
                                CookieManager cookieManager = CookieManager.getInstance();
                                cookieManager.setCookie(url, cookieName + "=" + cookieValue);

                                PluginResult res = new PluginResult(PluginResult.Status.OK, "Successfully added cookie");
                                callbackContext.sendPluginResult(res);
                            }
                            catch (Exception e) {
                                callbackContext.error(e.getMessage());
                            }
                        }
                    });

            return true;
        }
        catch(JSONException e) {
            callbackContext.error("JSON parsing error");
        }

        return false;
    }

    /**
     * sets cookie value under given key
     * @param args
     * @param callbackContext
     * @return boolean
     */
    private boolean  getMCookie(JSONArray args, final CallbackContext callbackContext) {
        try {
            final SharedPreferences prefs = Utils.getPreferences(this.cordova.getActivity().getApplicationContext());
            String cname = prefs.getString("CName", null);

            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(ALIAS, null);
            SecretKey secretKey2 = secretKeyEntry.getSecretKey();

            Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS7Padding");
            //OBtenemos el valor
            SharedPreferences prefs2 = Utils.getPreferences(this.cordova.getActivity().getApplicationContext());
            String iv2 = prefs2.getString("iv2", null);
            Log.i("CookieExplorer - SHARED ", iv2);
            //GCMParameterSpec spec = new GCMParameterSpec(128, Base64.decode(iv2, Base64.DEFAULT));
            IvParameterSpec ivParamsSpec = new IvParameterSpec(Base64.decode(iv2, Base64.DEFAULT));
            cipher2.init(Cipher.DECRYPT_MODE, secretKey2, ivParamsSpec);
            byte[] decodedData = cipher2.doFinal(encryption);
            String unencryptedString = new String(decodedData, "UTF-8");
            Log.i("CookieExplorer - DESEncriPTADA ", unencryptedString);

            JSONObject json = null;
            if (unencryptedString != "") {
                json = new JSONObject("{mCookie:\"" + unencryptedString + "\"}");
            }

            if (json != null) {
                PluginResult res = new PluginResult(PluginResult.Status.OK, json);
                callbackContext.sendPluginResult(res);
            }
            else {
                callbackContext.error("Cookie not found!");
            }

            return true;
        }
        catch(Exception e) {
            callbackContext.error("JSON parsing error");
        }

        return false;
    }
}