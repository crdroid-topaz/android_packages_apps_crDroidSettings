package com.crdroid.settings.preferences;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.provider.Settings;
import android.util.AttributeSet;
import android.util.Log;
import android.widget.ImageButton;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.preference.Preference;
import androidx.preference.PreferenceViewHolder;

import com.android.settings.R;

import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

public class KeyboxDataPreference extends Preference {

    private static final String TAG = "KeyboxDataPreference";
    private static final String SECURE_KEY = "keybox_data";
    private static final String MIME_TYPE_XML = "text/xml";

    private static final String TAG_NUMBER_OF_KEYBOXES = "NumberOfKeyboxes";
    private static final String TAG_KEY = "Key";
    private static final String TAG_PRIVATE_KEY = "PrivateKey";
    private static final String TAG_CERTIFICATE = "Certificate";
    private static final String ATTR_ALGORITHM = "algorithm";
    private static final String ATTR_FORMAT = "format";
    private static final String FORMAT_PEM = "pem";

    private static final String ALG_ECDSA = "ecdsa";
    private static final String ALG_RSA = "rsa";

    private static final String KEY_EC = "EC";
    private static final String KEY_RSA = "RSA";

    private ActivityResultLauncher<Intent> filePickerLauncher;

    public KeyboxDataPreference(Context context, AttributeSet attrs) {
        super(context, attrs);
        setLayoutResource(R.layout.keybox_data_pref);
    }

    public void setFilePickerLauncher(ActivityResultLauncher<Intent> launcher) {
        this.filePickerLauncher = launcher;
    }

    @Override
    public void onBindViewHolder(PreferenceViewHolder holder) {
        super.onBindViewHolder(holder);

        holder.itemView.setOnClickListener(v -> {
            if (filePickerLauncher != null) {
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.setType(MIME_TYPE_XML);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                filePickerLauncher.launch(intent);
            }
        });

        ImageButton delBtn = (ImageButton) holder.findViewById(R.id.delete_button);
        if (delBtn != null) {
            delBtn.setOnClickListener(v -> {
                Settings.Secure.putString(getContext().getContentResolver(), SECURE_KEY, null);
                showToast(R.string.keybox_data_cleared);
                callChangeListener(null);
            });
        }
    }

    public void handleFileSelected(Uri uri) {
        if (uri == null || !isXmlFile(uri)) {
            showToast(R.string.keybox_invalid_file);
            return;
        }

        try {
            try (var reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(getContext().getContentResolver().openInputStream(uri)))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                String xmlContent = sb.toString().replace("\uFEFF", "");
                List<Keybox> keyboxes = parseXml(xmlContent);

                if (keyboxes == null) {
                    showToast(R.string.keybox_invalid_xml);
                    return;
                }

                JSONObject jsonObject = new JSONObject();
                for (Keybox keybox : keyboxes) {
                    String algorithmPrefix = keybox.algorithm;
                    jsonObject.put(algorithmPrefix + ".PRIV", keybox.privateKey);
                    for (int i = 0; i < keybox.certificates.size(); i++) {
                        jsonObject.put(algorithmPrefix + ".CERT_" + (i + 1), keybox.certificates.get(i));
                    }
                }

                String jsonString = jsonObject.toString();
                Settings.Secure.putString(getContext().getContentResolver(), SECURE_KEY, jsonString);

                showToast(R.string.keybox_file_loaded);
                callChangeListener(jsonString);
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to read XML file", e);
            showToast(R.string.keybox_file_read_failed);
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse XML file", e);
            showToast(R.string.keybox_invalid_xml);
        }
    }

    private List<Keybox> parseXml(String xml) {
        List<Keybox> keyboxes = new ArrayList<>();
        Integer numberOfKeyboxes = null;

        try {
            XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
            XmlPullParser parser = factory.newPullParser();
            parser.setInput(new StringReader(xml));

            int eventType = parser.getEventType();
            String currentAlg = null;
            String currentPriv = null;
            List<String> currentCerts = new ArrayList<>();

            while (eventType != XmlPullParser.END_DOCUMENT) {
                if (eventType == XmlPullParser.START_TAG) {
                    switch (parser.getName()) {
                        case TAG_NUMBER_OF_KEYBOXES:
                            try {
                                numberOfKeyboxes = Integer.parseInt(parser.nextText().trim());
                            } catch (Exception ignore) {}
                            break;
                        case TAG_KEY:
                            String algValue = parser.getAttributeValue(null, ATTR_ALGORITHM);
                            currentAlg = (algValue != null && algValue.equalsIgnoreCase(ALG_ECDSA)) ? KEY_EC
                                    : (algValue != null && algValue.equalsIgnoreCase(ALG_RSA)) ? KEY_RSA : null;
                            currentCerts.clear();
                            currentPriv = null;
                            break;
                        case TAG_PRIVATE_KEY:
                            if (currentAlg == null || !isPemFormat(parser)) {
                                Log.w(TAG, "Skipping key due to invalid format or algorithm");
                                currentPriv = null;
                            } else {
                                currentPriv = parser.nextText().trim();
                            }
                            break;
                        case TAG_CERTIFICATE:
                            if (currentAlg == null || !isPemFormat(parser)) {
                                Log.w(TAG, "Skipping certificate due to invalid format or algorithm");
                            } else {
                                currentCerts.add(parser.nextText().trim());
                            }
                            break;
                    }
                } else if (eventType == XmlPullParser.END_TAG) {
                    if (parser.getName().equals(TAG_KEY) && currentAlg != null && currentPriv != null) {
                        keyboxes.add(new Keybox(currentAlg, currentPriv, new ArrayList<>(currentCerts)));
                        currentAlg = null;
                        currentPriv = null;
                        currentCerts.clear();
                    }
                }
                eventType = parser.next();
            }
        } catch (Exception e) {
            Log.e(TAG, "XML parsing failed", e);
            return null;
        }

        return !keyboxes.isEmpty() ? keyboxes : null;
    }

    private boolean isXmlFile(Uri uri) {
        String type = getContext().getContentResolver().getType(uri);
        return uri.toString().toLowerCase().endsWith(".xml") || MIME_TYPE_XML.equals(type);
    }

    private boolean isPemFormat(XmlPullParser parser) {
        String format = parser.getAttributeValue(null, ATTR_FORMAT);
        return FORMAT_PEM.equalsIgnoreCase(format);
    }

    private void showToast(int resId) {
        Toast.makeText(getContext(), getContext().getString(resId), Toast.LENGTH_SHORT).show();
    }

    // Data class for Keybox
    private static class Keybox {
        public final String algorithm;
        public final String privateKey;
        public final List<String> certificates;

        public Keybox(String algorithm, String privateKey, List<String> certificates) {
            this.algorithm = algorithm;
            this.privateKey = privateKey;
            this.certificates = certificates;
        }
    }
}
