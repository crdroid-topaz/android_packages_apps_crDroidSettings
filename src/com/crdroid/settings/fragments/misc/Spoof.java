/*
 * Copyright (C) 2025 AxionOS Project
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
package com.crdroid.settings.fragments.misc;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.preference.Preference;

import com.android.settings.R;
import com.crdroid.settings.preferences.KeyboxDataPreference;
import com.crdroid.settings.preferences.BasePreferenceFragment;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;

public class Spoof extends BasePreferenceFragment {

    private KeyboxDataPreference keyboxDataPreference;

    private Preference mGmsSpoof;
    private Preference mPifJsonFilePreference;
    private Preference mUpdateJsonButton;

    private Handler handler = new Handler(Looper.getMainLooper());

    private ActivityResultLauncher<Intent> keyboxFilePickerLauncher;
    private ActivityResultLauncher<Intent> pifJsonFilePickerLauncher;

    public Spoof() {
        super(R.xml.spoofing);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        keyboxFilePickerLauncher =
                registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        if (keyboxDataPreference != null) {
                            Intent data = result.getData();
                            if (data != null) {
                                keyboxDataPreference.handleFileSelected(data.getData());
                            }
                        }
                    }
                });

        pifJsonFilePickerLauncher =
                registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        Intent data = result.getData();
                        if (data != null && data.getData() != null) {
                            loadPifJson(data.getData());
                            Toast.makeText(requireContext(), R.string.toast_import_success, Toast.LENGTH_SHORT).show();
                        }
                    }
                });
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        keyboxDataPreference = (KeyboxDataPreference) findPreference("keybox_data_setting");
        if (keyboxDataPreference != null) {
            keyboxDataPreference.setFilePickerLauncher(keyboxFilePickerLauncher);
        }

        mGmsSpoof = findPreference(SYS_GMS_SPOOF);
        mPifJsonFilePreference = findPreference(KEY_PIF_JSON_FILE_PREFERENCE);
        mUpdateJsonButton = findPreference(KEY_UPDATE_JSON_BUTTON);

        if (mGmsSpoof != null) {
            mGmsSpoof.setOnPreferenceChangeListener((preference, newValue) -> true);
        }
        if (mPifJsonFilePreference != null) {
            mPifJsonFilePreference.setOnPreferenceClickListener(preference -> {
                openPifJsonFileSelector();
                return true;
            });
        }
        if (mUpdateJsonButton != null) {
            mUpdateJsonButton.setOnPreferenceClickListener(preference -> {
                updatePropertiesFromUrl(PIF_JSON_URL);
                return true;
            });
        }

        Preference showProps = findPreference("show_pif_properties");
        if (showProps != null) {
            showProps.setOnPreferenceClickListener(preference -> {
                showPropertiesDialog();
                return true;
            });
        }
    }

    private void openPifJsonFileSelector() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        pifJsonFilePickerLauncher.launch(intent);
    }

    private void showPropertiesDialog() {
        String keys = SystemProperties.get("persist.sys.propshooks_keys", "");
        if (TextUtils.isEmpty(keys)) {
            Toast.makeText(requireContext(), R.string.error_loading_properties, Toast.LENGTH_SHORT).show();
            return;
        }

        Map<String, String> commonKeys = new HashMap<>();
        commonKeys.put("MF", "MANUFACTURER");
        commonKeys.put("MD", "MODEL");
        commonKeys.put("FP", "FINGERPRINT");
        commonKeys.put("PR", "PRODUCT");
        commonKeys.put("DV", "DEVICE");
        commonKeys.put("SP", "SECURITY_PATCH");
        commonKeys.put("ISDK", "DEVICE_INITIAL_SDK_INT");

        String[] keysArray = keys.split(",");
        Map<String, String> map = new HashMap<>();
        for (String key : keysArray) {
            String fullKey = commonKeys.getOrDefault(key, key);
            map.put(fullKey, SystemProperties.get("persist.sys.propshooks_" + key, ""));
        }

        try {
            JSONObject displayJson = new JSONObject(map);
            String jsonString = displayJson.toString(4).replace("\\/", "/");
            new AlertDialog.Builder(requireContext())
                    .setTitle(R.string.show_pif_properties_title)
                    .setMessage(jsonString)
                    .setPositiveButton(android.R.string.ok, null)
                    .show();
        } catch (Exception e) {
            Log.e(TAG, "Error creating JSON for dialog", e);
        }
    }

    private void updatePropertiesFromUrl(String urlString) {
        new Thread(() -> {
            try {
                String json = new String(new java.net.URL(urlString).openStream().readAllBytes(), StandardCharsets.UTF_8);
                applyPifJson(new JSONObject(json));
            } catch (Exception e) {
                Log.e(TAG, "Error downloading or applying JSON", e);
                handler.post(() -> Toast.makeText(requireContext(), R.string.toast_spoofing_failure, Toast.LENGTH_LONG).show());
            }
        }).start();
    }

    private void loadPifJson(Uri uri) {
        try {
            if (requireActivity() != null) {
                try (java.io.InputStream inputStream = requireActivity().getContentResolver().openInputStream(uri)) {
                    if (inputStream != null) {
                        String json = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
                        applyPifJson(new JSONObject(json));
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error loading PIF JSON", e);
        }
    }

    private void applyPifJson(JSONObject jsonObject) {
        List<String> keys = new ArrayList<>();
        for (String key : jsonObject.keySet()) {
            String value = jsonObject.optString(key, "");
            String pifKey;
            switch (key) {
                case "MANUFACTURER":
                    pifKey = "MF";
                    break;
                case "MODEL":
                    pifKey = "MD";
                    break;
                case "FINGERPRINT":
                    pifKey = "FP";
                    break;
                case "PRODUCT":
                    pifKey = "PR";
                    break;
                case "DEVICE":
                    pifKey = "DV";
                    break;
                case "SECURITY_PATCH":
                    pifKey = "SP";
                    break;
                case "DEVICE_INITIAL_SDK_INT":
                    pifKey = "ISDK";
                    break;
                default:
                    pifKey = key;
            }
            SystemProperties.set("persist.sys.propshooks_" + pifKey, value);
            keys.add(pifKey);
        }

        String keysCsv = String.join(",", keys);
        SystemProperties.set("persist.sys.propshooks_keys", keysCsv);

        try {
            StringBuilder sb = new StringBuilder();
            keys.stream().sorted().forEach(k -> sb.append(k).append(SystemProperties.get("persist.sys.propshooks_" + k, "")));
            byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(sb.toString().getBytes());
            StringBuilder hash = new StringBuilder();
            for (byte b : hashBytes) {
                hash.append(String.format("%02x", b));
            }
            SystemProperties.set("persist.sys.propshooks_data_hash", hash.toString());
        } catch (Exception e) {
            Log.e(TAG, "Error computing hash", e);
        }

        handler.post(() -> {
            String spoofedModel = jsonObject.optString("MODEL", "Unknown model");
            Toast.makeText(requireContext(), getString(R.string.toast_spoofing_success, spoofedModel), Toast.LENGTH_LONG).show();
        });
    }

    private static final String TAG = "Spoof";
    private static final String SYS_GMS_SPOOF = "persist.sys.pixelprops.gms";
    private static final String KEY_PIF_JSON_FILE_PREFERENCE = "pif_json_file_preference";
    private static final String KEY_UPDATE_JSON_BUTTON = "update_pif_json";
    private static final String PIF_JSON_URL =
            "https://raw.githubusercontent.com/AxionAOSP/PlayIntegrityFix/refs/heads/lineage-22.1/pif.json";
}
