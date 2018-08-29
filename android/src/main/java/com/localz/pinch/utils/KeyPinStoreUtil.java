package com.localz.pinch.utils;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class KeyPinStoreUtil {

    private static HashMap<String[], KeyPinStoreUtil> instances = new HashMap<>();
    private SSLContext sslContext = SSLContext.getInstance("TLS");

    public static synchronized KeyPinStoreUtil getInstance(String[] filenames, String p12Name) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        if (filenames != null && instances.get(filenames) == null) {
            instances.put(filenames, new KeyPinStoreUtil(filenames, p12Name));
        }
        return instances.get(filenames);

    }

    private KeyPinStoreUtil(String[] filenames, String p12Name) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Create a KeyStore for our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);

        for (String filename : filenames) {
            InputStream caInput = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("assets/" + filename + ".cer"));
            Certificate ca;
            try {
                ca = cf.generateCertificate(caInput);
                System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());
            } finally {
                caInput.close();
            }

            keyStore.setCertificateEntry(filename, ca);
        }

        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        //Key Manager With the P12
        String p12KeyStore = "PKCS12";
        KeyStore pStore = KeyStore.getInstance(p12KeyStore);
        pStore.load(null, null);

        InputStream rawResource = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("assets/configuration.properties"));
        Properties properties = new Properties();
        String clientSecret = null;
        try{
            properties.load(rawResource);
            clientSecret = properties.getProperty(p12Name);
        } catch(Exception e){

        } finally{
            rawResource.close();
        }

        InputStream certInput12 = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("assets/" + p12Name + ".p12"));
        pStore.load(certInput12, clientSecret.toCharArray());

        // Create a KeyManager that uses our client cert
        String algorithm = KeyManagerFactory.getDefaultAlgorithm();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        try {
            kmf.init(pStore, null);
        } catch(UnrecoverableKeyException e){

        } finally{
            certInput12.close();
        }


        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    }

    public SSLContext getContext() {
        return sslContext;
    }
}
