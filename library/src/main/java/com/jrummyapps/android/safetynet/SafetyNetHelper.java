/*
 * Copyright (C) 2016 Jared Rummler <jared.rummler@gmail.com>
 * Copyright (C) 2015 Scott Alexander-Bown
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.jrummyapps.android.safetynet;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.IntDef;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks;
import com.google.android.gms.common.api.GoogleApiClient.OnConnectionFailedListener;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.security.DigestInputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * <a href="https://developer.android.com/training/safetynet/index.html">SafetyNet: Google's tamper detection.</a>
 */
public class SafetyNetHelper implements Runnable, OnConnectionFailedListener, ConnectionCallbacks {

  /**
   * The error code used when connecting with Google Play Services failed.
   */
  public static final int RESPONSE_FAILED_CONNECTION = 1;

  /**
   * The error code used when the SafetyNet Service failed.
   */
  public static final int RESPONSE_FAILED_ATTESTATION = 2;

  /**
   * The error code used when parsing the JSON Web Signature failed.
   */
  public static final int RESPONSE_FAILED_PARSING_JWS = 3;

  /**
   * URL to use the Android Device Verification API which only validates that the provided JWS message was received
   * from the SafetyNet service. The API allows for 10,000 requests per day.
   */
  private static final String GOOGLE_VERIFICATION_URL =
      "https://www.googleapis.com/androidcheck/v1/attestations/verify?key=";

  /**
   * This is used to validate the payload response from the SafetyNet.API, if it exceeds this duration, the response is
   * considered invalid.
   */
  private static final int MAX_TIMESTAMP_DURATION = 3 * 60 * 1000;

  private static final String SHA_256 = "SHA-256";
  private static final String TAG = "SafetyNetHelper";

  private static SecureRandom secureRandom;

  /**
   * Create a request to the {@link SafetyNet}.
   *
   * @param context
   *     the application context
   * @return A {@link Builder} object to create the {@link SafetyNetHelper}.
   */
  public static Builder with(Context context) {
    return new Builder(context);
  }

  /**
   * Validate the SafetyNet response using the Android Device Verification API. This API performs a validation check on
   * the JWS message returned from the SafetyNet service.
   *
   * <b>Important:</b> This use of the Android Device Verification API only validates that the provided JWS message was
   * received from the SafetyNet service. It <i>does not</i> verify that the payload data matches your original
   * compatibility check request.
   *
   * @param jws
   *     The output of {@link SafetyNetApi.AttestationResult#getJwsResult()}.
   * @param apiKey
   *     The Android Device Verification API key
   * @return {@code true} if the provided JWS message was received from the SafetyNet service.
   * @throws SafetyNetError
   *     if an error occurs while verifying the JSON Web Signature.
   */
  public static boolean validate(@NonNull String jws, @NonNull String apiKey) throws SafetyNetError {
    try {
      URL verifyApiUrl = new URL(GOOGLE_VERIFICATION_URL + apiKey);

      TrustManagerFactory trustManagerFactory =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init((KeyStore) null);
      TrustManager[] defaultTrustManagers = trustManagerFactory.getTrustManagers();
      TrustManager[] trustManagers = Arrays.copyOf(defaultTrustManagers, defaultTrustManagers.length + 1);
      trustManagers[defaultTrustManagers.length] = new GoogleApisTrustManager();

      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, trustManagers, null);

      HttpsURLConnection urlConnection = (HttpsURLConnection) verifyApiUrl.openConnection();
      urlConnection.setSSLSocketFactory(sslContext.getSocketFactory());
      urlConnection.setRequestMethod("POST");
      urlConnection.setRequestProperty("Content-Type", "application/json");

      JSONObject requestJson = new JSONObject();
      requestJson.put("signedAttestation", jws);
      byte[] outputInBytes = requestJson.toString().getBytes("UTF-8");
      OutputStream os = urlConnection.getOutputStream();
      os.write(outputInBytes);
      os.close();

      urlConnection.connect();
      InputStream is = urlConnection.getInputStream();
      BufferedReader reader = new BufferedReader(new InputStreamReader(is));
      StringBuilder sb = new StringBuilder();
      for (String line = reader.readLine(), nl = ""; line != null; line = reader.readLine(), nl = "\n") {
        sb.append(nl).append(line);
      }

      return new JSONObject(sb.toString()).getBoolean("isValidSignature");
    } catch (Exception e) {
      throw new SafetyNetError(e);
    }
  }

  /**
   * Parse the JSON Web Signature (JWS) response from the {@link SafetyNet} response.
   *
   * @param jws
   *     The output of {@link SafetyNetApi.AttestationResult#getJwsResult()}.
   * @return The {@link SafetyNetResponse}.
   * @throws SafetyNetError
   *     If an error occurs while parsing the JWS.
   */
  public static SafetyNetResponse getSafetyNetResponseFromJws(@NonNull String jws) throws SafetyNetError {
    try {
      String[] parts = jws.split("\\.");

      HashMap<String, Object> header = new HashMap<>();

      try {
        JSONObject json = new JSONObject(new String(Base64.decode(parts[0], Base64.DEFAULT)));
        for (Iterator<String> iterator = json.keys(); iterator.hasNext(); ) {
          String key = iterator.next();
          header.put(key, json.get(key));
        }
      } catch (Exception ignored) {
      }

      JSONObject json = new JSONObject(new String(Base64.decode(parts[1], Base64.DEFAULT)));
      String nonce = json.optString("nonce");
      long timestampMs = json.optLong("timestampMs");
      String apkPackageName = json.optString("apkPackageName");

      JSONArray jsonArray = json.optJSONArray("apkCertificateDigestSha256");
      String[] apkCertificateDigestSha256 = null;
      if (jsonArray != null) {
        int length = jsonArray.length();
        apkCertificateDigestSha256 = new String[length];
        for (int i = 0; i < length; i++) {
          apkCertificateDigestSha256[i] = jsonArray.getString(i);
        }
      }

      String apkDigestSha256 = json.optString("apkDigestSha256");
      boolean ctsProfileMatch = json.optBoolean("ctsProfileMatch");
      String signature = parts[2];

      return new SafetyNetResponse(jws,
          header,
          nonce,
          timestampMs,
          apkPackageName,
          apkCertificateDigestSha256,
          apkDigestSha256,
          ctsProfileMatch,
          signature);

    } catch (Exception e) {
      throw new SafetyNetError(e);
    }
  }

  /**
   * Generates a random token.
   *
   * @return A nonce, with a length of 32, to be used with the {@link SafetyNet} request.
   */
  public static byte[] generateOneTimeNonce() {
    if (secureRandom == null) {
      secureRandom = new SecureRandom();
    }
    byte[] nonce = new byte[32];
    secureRandom.nextBytes(nonce);
    return nonce;
  }

  private final Context context;
  private final Handler handler;
  private final Set<SafetyNetListener> listeners;
  private final byte[] nonce;
  private final String apiKey;
  private GoogleApiClient googleApiClient;
  private long requestTimestamp;
  private boolean cancel;

  private SafetyNetHelper(Builder builder) {
    this.context = builder.context;
    this.handler = builder.handler;
    this.listeners = builder.listeners;
    this.nonce = builder.nonce;
    this.apiKey = builder.apiKey;
  }

  @Override public void run() {
    googleApiClient = new GoogleApiClient.Builder(context)
        .addOnConnectionFailedListener(this)
        .addConnectionCallbacks(this)
        .addApi(SafetyNet.API)
        .build();
    googleApiClient.connect();
  }

  @Override public void onConnectionFailed(@NonNull ConnectionResult connectionResult) {
    onError(RESPONSE_FAILED_CONNECTION, "An error occurred while connecting with Google Play Services.");
  }

  @Override public void onConnected(@Nullable Bundle bundle) {
    Runnable runnable = new Runnable() {

      @Override public void run() {
        requestTimestamp = System.currentTimeMillis();
        SafetyNetApi.AttestationResult result = SafetyNet.SafetyNetApi.attest(googleApiClient, nonce).await();
        if (cancel) {
          return;
        }
        if (!result.getStatus().isSuccess()) {
          onError(RESPONSE_FAILED_ATTESTATION, "An error occurred while communicating with SafetyNet.");
          return;
        }
        try {
          SafetyNetResponse response = getSafetyNetResponseFromJws(result.getJwsResult());
          SafetyNetVerification verification = verify(response);
          onFinished(response, verification);
        } catch (SafetyNetError e) {
          onError(RESPONSE_FAILED_PARSING_JWS, e.getLocalizedMessage());
        }
      }
    };

    if (Looper.getMainLooper() == Looper.myLooper()) {
      new Thread(runnable).start();
    } else {
      runnable.run();
    }
  }

  @Override public void onConnectionSuspended(int reason) {
    onError(RESPONSE_FAILED_CONNECTION, "An error occurred while connecting with Google Play Services.");
  }

  /**
   * Cancel running or posting the results
   */
  public void cancel() {
    cancel = true;
  }

  private void onError(@SafetyNetErrorCode final int errorCode, final String reason) {
    if (!cancel) {
      handler.post(new Runnable() {

        @Override public void run() {
          for (SafetyNetListener listener : listeners) {
            listener.onError(errorCode, reason);
          }
        }
      });
    }
  }

  private void onFinished(final SafetyNetResponse response, final SafetyNetVerification verification) {
    if (!cancel) {
      handler.post(new Runnable() {

        @Override public void run() {
          for (SafetyNetListener listener : listeners) {
            listener.onFinished(response, verification);
          }
        }
      });
    }
  }

  private SafetyNetVerification verify(SafetyNetResponse response) {
    Boolean isValidSignature = null;
    if (!TextUtils.isEmpty(apiKey)) {
      try {
        isValidSignature = validate(response.jws, apiKey);
      } catch (SafetyNetError e) {
        Log.d(TAG, "An error occurred while using the Android Device Verification API", e);
      }
    }

    String nonce = Base64.encodeToString(this.nonce, Base64.DEFAULT).trim();
    boolean isValidNonce = TextUtils.equals(nonce, response.nonce);

    long durationOfReq = response.timestampMs - requestTimestamp;
    boolean isValidResponseTime = durationOfReq < MAX_TIMESTAMP_DURATION;

    boolean isValidApkSignature = true;
    if (response.apkCertificateDigestSha256 != null && response.apkCertificateDigestSha256.length > 0) {
      isValidApkSignature = Arrays.equals(getApkCertificateDigests().toArray(), response.apkCertificateDigestSha256);
    }

    boolean isValidApkDigest = true;
    if (!TextUtils.isEmpty(response.apkDigestSha256)) {
      isValidApkDigest = TextUtils.equals(getApkDigestSha256(), response.apkDigestSha256);
    }

    return new SafetyNetVerification(isValidSignature,
        isValidNonce,
        isValidResponseTime,
        isValidApkSignature,
        isValidApkDigest);
  }

  @Nullable private String getApkDigestSha256() {
    try {
      FileInputStream fis = new FileInputStream(context.getPackageCodePath());
      MessageDigest md = MessageDigest.getInstance(SHA_256);
      try {
        DigestInputStream dis = new DigestInputStream(fis, md);
        byte[] buffer = new byte[2048];
        while (dis.read(buffer) != -1) {
          //
        }
        dis.close();
      } finally {
        fis.close();
      }
      return Base64.encodeToString(md.digest(), Base64.NO_WRAP);
    } catch (IOException | NoSuchAlgorithmException e) {
      return null;
    }
  }

  @SuppressLint("PackageManagerGetSignatures")
  private List<String> getApkCertificateDigests() {
    List<String> apkCertificateDigests = new ArrayList<>();
    PackageManager pm = context.getPackageManager();
    PackageInfo packageInfo;
    try {
      packageInfo = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
    } catch (PackageManager.NameNotFoundException wtf) {
      return apkCertificateDigests;
    }
    Signature[] signatures = packageInfo.signatures;
    for (Signature signature : signatures) {
      try {
        MessageDigest md = MessageDigest.getInstance(SHA_256);
        md.update(signature.toByteArray());
        byte[] digest = md.digest();
        apkCertificateDigests.add(Base64.encodeToString(digest, Base64.NO_WRAP));
      } catch (NoSuchAlgorithmException ignored) {
      }
    }
    return apkCertificateDigests;
  }

  /**
   * The {@link SafetyNet} API payload response (decoded from the JSON Web Token).
   */
  public static class SafetyNetResponse {

    /** The value of {@link SafetyNetApi.AttestationResult#getJwsResult()} */
    public final String jws;
    /** The headers from the JSON Web Signature */
    public final HashMap<String, Object> header;
    /** The requested nonce */
    public final String nonce;
    /** The timestamp of the request */
    public final long timestampMs;
    /** The package name of the requesting app */
    public final String apkPackageName;
    /** The APK signature(s) of the requesting app */
    public final String[] apkCertificateDigestSha256;
    /** The APK digest of the requesting app */
    public final String apkDigestSha256;
    /** {@code true} if the device passed the compatibility test */
    public final boolean ctsProfileMatch;
    /** The JWS signature */
    public final String signature;

    SafetyNetResponse(String jws,
                      HashMap<String, Object> header,
                      String nonce,
                      long timestampMs,
                      String apkPackageName,
                      String[] apkCertificateDigestSha256,
                      String apkDigestSha256,
                      boolean ctsProfileMatch,
                      String signature) {
      this.jws = jws;
      this.header = header;
      this.nonce = nonce;
      this.timestampMs = timestampMs;
      this.apkPackageName = apkPackageName;
      this.apkCertificateDigestSha256 = apkCertificateDigestSha256;
      this.apkDigestSha256 = apkDigestSha256;
      this.ctsProfileMatch = ctsProfileMatch;
      this.signature = signature;
    }

  }

  /**
   * Validates the {@link SafetyNet} response.
   */
  public static class SafetyNetVerification {

    /**
     * The response from the Android Device Verification API. If the apiKey was not set then this is {@code null}
     */
    @Nullable public final Boolean isValidSignature;

    /**
     * {@code true} if the request nonce matches the nonce returned from the {@link SafetyNet} result.
     */
    public final boolean isValidNonce;

    /**
     * {@code true} if the payload response took more than {@value MAX_TIMESTAMP_DURATION} milliseconds.
     */
    public final boolean isValidResponseTime;

    /**
     * {@code true} if the payload's "apkCertificateDigestSha256" matches the signature of this APK.
     */
    public final boolean isValidApkSignature;

    /**
     * {@code true} if the payload's "apkDigestSha256" matches the digest of this APK.
     */
    public final boolean isValidApkDigest;

    SafetyNetVerification(@Nullable Boolean isValidSignature,
                          boolean isValidNonce,
                          boolean isValidResponseTime,
                          boolean isValidApkSignature,
                          boolean isValidApkDigest) {
      this.isValidSignature = isValidSignature;
      this.isValidNonce = isValidNonce;
      this.isValidResponseTime = isValidResponseTime;
      this.isValidApkSignature = isValidApkSignature;
      this.isValidApkDigest = isValidApkDigest;
    }

    /**
     * Check if the {@link SafetyNet} response is valid.
     *
     * @return {@code true} if the response from {@link SafetyNet} is verified and valid.
     */
    public boolean isValid() {
      return (isValidSignature == null ? true /* No API key to check the response. Assume true. */ : isValidSignature)
          && isValidNonce && isValidResponseTime && isValidApkSignature && isValidApkDigest;
    }

  }

  /**
   * An exception used when retrieving or parsing a response from the {@link SafetyNet} API failed.
   */
  public static class SafetyNetError extends Exception {

    public SafetyNetError(Throwable cause) {
      super(cause);
    }

  }

  @IntDef({RESPONSE_FAILED_ATTESTATION, RESPONSE_FAILED_CONNECTION, RESPONSE_FAILED_PARSING_JWS})
  public @interface SafetyNetErrorCode {

  }

  /**
   * Interface definition for a callback to be invoked during/after the {@link SafetyNet} API is queried.
   */
  public interface SafetyNetListener {

    /**
     * Called when an error occurs while trying to receive a response from the {@link SafetyNet} API.
     *
     * @param errorCode
     *     The error code
     * @param reason
     *     The error reason
     */
    void onError(@SafetyNetErrorCode int errorCode, String reason);

    /**
     * Called when the {@link SafetyNet} API returns a valid response.
     *
     * @param response
     *     The {@link SafetyNet} API response
     * @param verification
     *     Contains info about the validity of the response.
     */
    void onFinished(SafetyNetResponse response, SafetyNetVerification verification);

  }

  /**
   * Custom TrustManager to use SSL public key Pinning to verify connections to www.googleapis.com
   * Created by scottab on 27/05/2015.
   */
  public static class GoogleApisTrustManager implements X509TrustManager {

    private final static String[] GOOGLEAPIS_COM_PINS = {
        "sha1/f2QjSla9GtnwpqhqreDLIkQNFu8=",
        "sha1/Q9rWMO5T+KmAym79hfRqo3mQ4Oo=",
        "sha1/wHqYaI2J+6sFZAwRfap9ZbjKzE4="
    };

    @SuppressLint("TrustAllX509TrustManager")
    @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      // No-Op
    }

    @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      for (X509Certificate cert : chain) {
        boolean expected = validateCertificatePin(cert);
        if (!expected) {
          throw new CertificateException("could not find a valid SSL public key pin for www.googleapis.com");
        }
      }
    }

    @Override public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }

    private boolean validateCertificatePin(X509Certificate certificate) throws CertificateException {

      MessageDigest digest;
      try {
        digest = MessageDigest.getInstance("SHA1");
      } catch (NoSuchAlgorithmException e) {
        throw new CertificateException(e);
      }

      byte[] pubKeyInfo = certificate.getPublicKey().getEncoded();
      byte[] pin = digest.digest(pubKeyInfo);
      String pinAsBase64 = "sha1/" + Base64.encodeToString(pin, Base64.DEFAULT);
      for (String validPin : GOOGLEAPIS_COM_PINS) {
        if (validPin.equalsIgnoreCase(pinAsBase64)) {
          return true;
        }
      }
      return false;
    }

  }

  public static class Builder {

    final Set<SafetyNetListener> listeners = new HashSet<>();
    final Context context;
    Handler handler;
    String apiKey;
    byte[] nonce;

    Builder(@NonNull Context context) {
      this.context = context.getApplicationContext();
    }

    /**
     * Set the {@link SafetyNetListener}.
     *
     * @param listener
     *     The {@link SafetyNetListener} to receive callbacks on the UI thread.
     * @return this {@link Builder} object for chaining method calls.
     */
    public Builder addSafetyNetListener(@NonNull SafetyNetListener listener) {
      this.listeners.add(listener);
      return this;
    }

    /**
     * Set the nonce used in the {@link SafetyNet} request.
     *
     * @param nonce
     *     A nonce used with a SafetyNet request should be at least 16 bytes in length.
     * @return this {@link Builder} object for chaining method calls.
     */
    public Builder setNonce(@NonNull byte[] nonce) {
      this.nonce = nonce;
      return this;
    }

    /**
     * Set the {@link Handler} that is used to post callbacks.
     *
     * @param handler
     *     The {@link Handler}
     * @return this {@link Builder} object for chaining method calls.
     */
    public Builder setHandler(@NonNull Handler handler) {
      this.handler = handler;
      return this;
    }

    /**
     * Set the Android Device Verification API key. If set to {@code null} then the request will not be validated.
     *
     * @param apiKey
     *     The API key for the Android Device Verification API.
     * @return this {@link Builder} object for chaining method calls.
     */
    public Builder setApiKey(@NonNull String apiKey) {
      this.apiKey = apiKey;
      return this;
    }

    /**
     * Run the {@link SafetyNet} request.
     */
    public SafetyNetHelper run() {
      if (nonce == null) {
        nonce = generateOneTimeNonce();
      }
      if (handler == null) {
        handler = new Handler(Looper.getMainLooper());
      }
      SafetyNetHelper safetyNetHelper = new SafetyNetHelper(this);
      safetyNetHelper.run();
      return safetyNetHelper;
    }

  }

}
