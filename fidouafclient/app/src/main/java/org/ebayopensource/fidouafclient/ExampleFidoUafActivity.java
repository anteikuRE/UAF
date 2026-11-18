/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ebayopensource.fidouafclient;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.client.op.Auth;
import org.ebayopensource.fido.uaf.client.op.Reg;
import org.ebayopensource.fido.uaf.crypto.FidoKeystore;
import org.ebayopensource.fido.uaf.crypto.FidoSigner;
import org.ebayopensource.fido.uaf.crypto.FidoSignerAndroidM;
import org.ebayopensource.fido.uaf.crypto.FidoSignerBC;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fidouafclient.fp.FingerprintAuthProcessor;
import org.ebayopensource.fidouafclient.fp.FingerprintAuthenticationDialogFragment;
import org.ebayopensource.fidouafclient.util.Preferences;
import org.json.JSONArray;
import org.json.JSONObject;
import org.ebayopensource.fido.uaf.client.RegAssertionBuilder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ExampleFidoUafActivity extends Activity implements FingerprintAuthProcessor {

    private static final String TAG = ExampleFidoUafActivity.class.getSimpleName();

    private static final Logger logger = Logger.getLogger(ExampleFidoUafActivity.class.getName());

    private Gson gson = new Gson();
    private TextView operation;
    private TextView uafMsg;
    private Reg regOp;
    private Auth authOp = new Auth();
    private KeyguardManager keyguardManager;
    private int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;

    private static final String DIALOG_FRAGMENT_TAG = "fpDialogFragment";

    private String authReq;

    private FidoKeystore fidoKeystore;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.d(TAG, "onCreate called, about to processOpAndFinish");
        fidoKeystore = FidoKeystore.createKeyStore(getApplicationContext());
        keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        Bundle extras = this.getIntent().getExtras();
        setContentView(R.layout.activity_fido_uaf);
        operation = (TextView) findViewById(R.id.textViewOperation);
        uafMsg = (TextView) findViewById(R.id.textViewOpMsg);
        operation.setText(extras.getString("UAFIntentType"));
        uafMsg.setText(extras.getString("message"));
        Log.d(TAG, "about to call processOpAndFinish");
        // NOTE | IMPORTANT: method below responsible for disabling check of user presence and user verification (pin whatever)
//        processOpAndFinish();
    }

    private static final short ERR_NO_SUITABLE_AUTHENTICATOR = 0x03;
    private static final short ERR_PROTOCOL_ERROR = 0x07;

    private void processOpAndFinish() {
        String inMsg = this.getIntent().getExtras().getString("message");
        String mimeType = this.getIntent().getType();
        String intentType = this.getIntent().getExtras().getString("UAFIntentType");
        Log.d(TAG, "intentType " + intentType + ", inMsg " + inMsg);

        // DISCOVER carries no message (UAF client intent API), so it must be answered before the
        // empty-message check below; otherwise the activity never finishes and the caller hangs.
        if (!"application/fido.uaf_asm+json".equals(mimeType)) {
            if ("DISCOVER".equals(intentType)) {
                processDiscover();
                return;
            }
            if ("CHECK_POLICY".equals(intentType)) {
                processCheckPolicy(inMsg);
                return;
            }
        }

        if (inMsg != null && inMsg.length() > 0) {
            if ("application/fido.uaf_asm+json".equals(mimeType)) {
                processAsmOp(inMsg);
            } else {
                processOp(inMsg); // Standard Client requests
            }
        } else {
            Log.w(TAG, "inMsg is empty");
        }
    }
    private void processDiscover() {
        try {
            JSONObject v11 = new JSONObject().put("major", 1).put("minor", 1);
            JSONObject v12 = new JSONObject().put("major", 1).put("minor", 2);

            JSONObject authenticator = new JSONObject()
                    .put("title", "eBay UAF Authenticator")
                    .put("aaid", RegAssertionBuilder.AAID)
                    .put("description", "eBay UAF demo authenticator")
                    .put("supportedUAFVersions", new JSONArray().put(v11).put(v12))
                    .put("assertionScheme", "UAFV1TLV")
                    .put("authenticationAlgorithm", 1)
                    .put("attestationTypes", new JSONArray().put(15879))
                    .put("userVerification", 2)
                    .put("keyProtection", 1)
                    .put("matcherProtection", 1)
                    .put("attachmentHint", 1)
                    .put("isSecondFactorOnly", false)
                    .put("tcDisplay", 0)
                    .put("supportedExtensionIDs", new JSONArray());

            JSONObject discoveryData = new JSONObject()
                    .put("supportedUAFVersions", new JSONArray().put(v11).put(v12))
                    .put("clientVendor", "eBay")
                    .put("clientVersion", v12)
                    .put("availableAuthenticators", new JSONArray().put(authenticator));

            Bundle data = new Bundle();
            data.putString("UAFIntentType", "DISCOVER_RESULT");
            data.putString("discoveryData", discoveryData.toString());
            data.putShort("errorCode", (short) 0x0);
            Intent intent = new Intent();
            intent.putExtras(data);
            setResult(RESULT_OK, intent);
            finish();
        } catch (Exception e) {
            Log.e(TAG, "DISCOVER failed: " + e.getMessage(), e);
            returnTypedErrorAndFinish("DISCOVER_RESULT", ERR_PROTOCOL_ERROR);
        }
    }

    private void processCheckPolicy(String inUafOperationMsg) {
        short errorCode = 0x0;
        try {
            String inMsg = extract(inUafOperationMsg);
            JSONArray requests = new JSONArray(inMsg);
            JSONArray accepted = requests.getJSONObject(0)
                    .getJSONObject("policy").optJSONArray("accepted");
            boolean anyAaidListed = false;
            boolean ours = false;
            if (accepted != null) {
                for (int i = 0; i < accepted.length(); i++) {
                    JSONArray group = accepted.getJSONArray(i);
                    for (int j = 0; j < group.length(); j++) {
                        JSONArray aaids = group.getJSONObject(j).optJSONArray("aaid");
                        if (aaids == null) continue;
                        for (int k = 0; k < aaids.length(); k++) {
                            anyAaidListed = true;
                            if (RegAssertionBuilder.AAID.equalsIgnoreCase(aaids.getString(k))) ours = true;
                        }
                    }
                }
            }
            if (anyAaidListed && !ours) errorCode = ERR_NO_SUITABLE_AUTHENTICATOR;
        } catch (Exception e) {
            Log.e(TAG, "CHECK_POLICY failed: " + e.getMessage(), e);
            errorCode = ERR_PROTOCOL_ERROR;
        }
        returnTypedErrorAndFinish("CHECK_POLICY_RESULT", errorCode);
    }

    private void returnTypedErrorAndFinish(String resultType, short errorCode) {
        Bundle data = new Bundle();
        data.putString("UAFIntentType", resultType);
        data.putShort("errorCode", errorCode);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        finish();
    }

    private void processAsmOp(String inMsg) {
        Log.d(TAG, "processAsmOp: " + inMsg);
        try {
            if (inMsg.contains("\"GetInfo\"")) {
                Log.d(TAG, "op=GetInfo");

                String getInfoResponse = "{" +
                        "\"statusCode\": 0, " +
                        "\"responseData\": {" +
                        "\"Authenticators\": [{" +
                        "\"authenticatorIndex\": 0, " + // Match the index requested by OpenSettings
                        "\"asmVersions\": [{\"major\": 1, \"minor\": 1}, {\"major\": 1, \"minor\": 2}], " +
                        "\"isUserPresenceAndVerificationSupported\": true, " +
                        "\"isSecondFactorOnly\": false, " +
                        "\"assertionScheme\": \"UAFV1TLV\", " +
                        "\"attachmentHint\": 1, " +
                        "\"tcDisplay\": 0, " +
                        "\"authenticationAlgorithm\": 1, " +
                        "\"publicKeyAlgAndEncoding\": 256, " +
                        "\"attestationTypes\": [15879], " +
                        "\"userVerification\": 2, " +
                        "\"keyProtection\": 1, " +
                        "\"matcherProtection\": 1, " +
                        "\"cryptoStrength\": 128, " +
                        "\"aaguid\": \"00000000-0000-0000-0000-000000000000\"" +
                        "}]}}";

                returnAsmResultAndFinish(getInfoResponse);
                Log.d(TAG, "FINISHING UP GetInfo");

            } else if (inMsg.contains("\"OpenSettings\"")) {
                Log.d(TAG, "op=OpenSettings");

                // Return a simple success status for OpenSettings
                String openSettingsResponse = "{\"statusCode\": 0}";

                returnAsmResultAndFinish(openSettingsResponse);
                Log.d(TAG, "FINISHING UP OpenSettings");

            } else {
                // Catch Register, Authenticate, Deregister, or unknown commands
                Log.w(TAG, "ASM_ERROR: Unhandled ASM operation. Returning ERR_UNKNOWN (0x01)");
                returnAsmErrorAndFinish((short) 0x01);
            }
        } catch (Exception e) {
            Log.e(TAG, "ASM Error processing request: " + e.getMessage(), e);
            // Catch JSON parsing failures
            returnAsmErrorAndFinish((short) 0x01);
        }
    }
    private void returnAsmResultAndFinish(String msg) {
        Bundle data = new Bundle();
        data.putString("message", msg);
        data.putString("ASMIntentType", "ASMCall_Result"); // Satisfies KMP onActivityResult
        data.putShort("errorCode", (short) 0x0);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        Log.d(TAG, "FINISHING UP");
        finish();
    }
    private void returnAsmErrorAndFinish(short errorCode) {
        Bundle data = new Bundle();

        // The FIDO ASM spec requires the statusCode to be in the JSON payload
        String errorJson = "{\"statusCode\": " + errorCode + "}";
        data.putString("message", errorJson);

        // Satisfy the KMP transport layer's strict Intent Type checks
        data.putString("ASMIntentType", "ASMCall_Result");
        data.putShort("errorCode", errorCode);

        Intent intent = new Intent();
        intent.putExtras(data);

        // Using RESULT_OK ensures it passes the Android activity check in KMP,
        // but the errorCode > 0 will trigger your `onProcessRequestError` callback.
        setResult(RESULT_OK, intent);
        Log.d(TAG, "FINISHING UP ERR");
        finish();
    }
    private void finishWithError(String errorMessage) {
        Bundle data = new Bundle();
        data.putString("message", errorMessage);
        data.putString("UAFIntentType", "UAF_OPERATION_RESULT");
        data.putShort("errorCode", (short) 0x01);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_CANCELED, intent);
        finish();
    }
//    private void finishWithError(String errorMessage) {
//        Bundle data = new Bundle();
//
//        data.putString("message", errorMessage);
//        Intent intent = new Intent();
//        intent.putExtras(data);
//        setResult(RESULT_CANCELED, intent);
//        finish();
//    }


    private void processOp(String inUafOperationMsg) {
        Log.d(TAG, "processOp: " + inUafOperationMsg);
        try {
            final String inMsg = extract(inUafOperationMsg);

            if (inMsg == null || inMsg.isEmpty()) {
                finishWithError("PROTOCOL_ERROR: could not extract uafProtocolMessage");
                return;
            }

            if (inMsg.contains("\"Reg\"")) {
                Log.d(TAG, "op=Reg");
                RegistrationRequest regRequest = gson.fromJson(inMsg, RegistrationRequest[].class)[0];
                // NOTE | IMPORTANT: Authorization only works with real UV (cant use processOpAndFinish)
                Preferences.setSettingsParam("username", regRequest.username);
                String facetId = // get it from Intent extras, passed from your Kotlin code
                        this.getIntent().getExtras().getString("facetId", "");
                regOp = new Reg(regRequest.username, fidoKeystore, facetId);
                String msg = regOp.register(inMsg);
                returnResultAndFinish(msg);
            } else if (inMsg.contains("\"Auth\"")) {
                Log.d(TAG, "op=Auth");
                authReq = inMsg;
                String username = Preferences.getSettingsParam("username");
                Log.d(TAG, "username: " + username);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    if (supportsFingerprintAuth()) {
                        startFingerprintAuth();
                    } else {
                        FidoSigner fidoSigner = createFidoSigner();
                        String authMsg = authOp.auth(authReq, fidoSigner, null);
                        returnResultAndFinish(authMsg);
                    }
                } else {
                    FidoSigner fidoSigner = new FidoSignerBC();
                    KeyPair keyPair = fidoKeystore.getKeyPair(username);
                    String msg = authOp.auth(authReq, fidoSigner, keyPair);
                    returnResultAndFinish(msg);
                }
            } else if (inMsg.contains("\"Dereg\"")) {
                Log.d(TAG, "op=Dereg");
                returnResultAndFinish(inUafOperationMsg);
            } else {
                finishWithError("PROTOCOL_ERROR: unknown or missing operation");
            }
        } catch (Exception e) {
            String errorMessage = "Error: " + e.getMessage();
            Log.e(TAG, errorMessage, e);
            finishWithError(errorMessage);
        }
    }

    @NonNull
    private FidoSigner createFidoSigner() throws NoSuchAlgorithmException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        PrivateKey privateKey = fidoKeystore.getKeyPair(Preferences.getSettingsParam("username")).getPrivate();
        signature.initSign(privateKey);

        return new FidoSignerAndroidM(signature);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void startFingerprintAuth() throws GeneralSecurityException, IOException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        PrivateKey privateKey = fidoKeystore.getKeyPair(Preferences.getSettingsParam("username")).getPrivate();
        signature.initSign(privateKey);

        FingerprintAuthenticationDialogFragment fragment
                = new FingerprintAuthenticationDialogFragment();
        FingerprintManager.CryptoObject cryptoObj = new FingerprintManager.CryptoObject(signature);
        fragment.setCryptoObject(cryptoObj);
        fragment.setStage(
                FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);

        Log.d(TAG, "Showing fragment: " + fragment);
        fragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
    }
    private void returnResultAndFinish(String msg) {
        Bundle data = new Bundle();
        data.putString("message", msg);
        data.putString("UAFIntentType", "UAF_OPERATION_RESULT");
        data.putShort("errorCode", (short) 0x0);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        finish();
    }
//    private void returnResultAndFinish(String msg) {
//        Bundle data = new Bundle();
//        data.putString("message", msg);
//        Intent intent = new Intent();
//        intent.putExtras(data);
//        setResult(RESULT_OK, intent);
//        finish();
//    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void processAuthentication(FingerprintManager.CryptoObject cryptObj) {
        FidoSigner fidoSigner = new FidoSignerAndroidM(cryptObj.getSignature());
        // fido signer doesn't need key pair, handled internally
        String msg = authOp.auth(authReq, fidoSigner, null);

        returnResultAndFinish(msg);
    }

    private static boolean isAndroidM() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return true;
        }

        return false;
    }

    private boolean supportsFingerprintAuth() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            FingerprintManager fingerprintManager = getSystemService(FingerprintManager.class);

            // noinspection ResourceType
            return fingerprintManager.isHardwareDetected()
                    && fingerprintManager.hasEnrolledFingerprints();
        }

        return false;
     }

    public void proceed(View view) {
        if (isAuthOp() && isAndroidM() && supportsFingerprintAuth()) {
            // Android M does fingerprint auth internally, so we don't call confirmDeviceCredential()
            processOpAndFinish();
        } else {
            confirmDeviceCredential();
        }
    }

    private boolean isAuthOp() {
        // XXX uglish, needed to avoid double auth in case of Android M+
        String inMsg = extract(getIntent().getExtras().getString("message"));
        if (inMsg.contains("\"Auth\"")) {
            Log.d(TAG, "op=Auth");
            return true;
        }

        return false;
    }

    private void confirmDeviceCredential() {
        Intent intent = keyguardManager.createConfirmDeviceCredentialIntent("UAF", "Confirm Identity");
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        } else {
            finishWithError("Unable to complete local authentication, please setup android device authentication(pin, pattern, fingerprint..)");
        }
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            // Challenge completed, proceed with using cipher
            if (resultCode == RESULT_OK) {
                processOpAndFinish();
            } else {
                // The user canceled or didn’t complete the lock screen
                // operation. Go to error/cancellation flow.
                String errorMessage = "User cancelled credential verification";
                Log.w(TAG, errorMessage);
                finishWithError(errorMessage);
            }
        }
    }

    public void back(View view) {
        Bundle data = new Bundle();
        String msg = "";
        logger.info("Registration canceled by user");
        data.putString("message", msg);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        finish();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            startActivity(new Intent(
                    "org.ebayopensource.fidouafclient.SettingsActivity"));
        }
        if (id == R.id.action_save_message) {
            SaveMessageDialog.show(this, uafMsg);
        }
        return super.onOptionsItemSelected(item);
    }
    private String extract(String inMsg) {
        try {
            JSONObject tmpJson = new JSONObject(inMsg);
            // Try getting as string first
            try {
                return tmpJson.getString("uafProtocolMessage");
            } catch (Exception e) {
                // If it's not a string, get it as array/object
                return tmpJson.get("uafProtocolMessage").toString();
            }
        } catch (Exception e) {
            logger.log(Level.WARNING, "Input message is invalid!", e);
            return "";
        }
    }
//    private String extract(String inMsg) {
//        try {
//            JSONObject tmpJson = new JSONObject(inMsg);
//            String uafMsg = tmpJson.getString("uafProtocolMessage");
//            uafMsg.replace("\\\"", "\"");
//            return uafMsg;
//        } catch (Exception e) {
//            logger.log(Level.WARNING, "Input message is invalid!", e);
//            return "";
//        }
//
//    }
}
