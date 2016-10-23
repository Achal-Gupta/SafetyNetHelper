/*
 * Copyright (C) 2016 Jared Rummler <jared.rummler@gmail.com>
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

package com.jrummyapps.safetynet.demo;

import android.graphics.Color;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.Spanned;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import com.jrummyapps.android.safetynet.SafetyNetHelper;

public class MainActivity extends AppCompatActivity {

  SafetyNetHelper safetyNetHelper;
  TextView resultText;
  EditText apiKey;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    apiKey = (EditText) findViewById(R.id.apiKey);
    resultText = (TextView) findViewById(R.id.result);
  }

  @Override protected void onStop() {
    super.onStop();
    if (safetyNetHelper != null) {
      safetyNetHelper.cancel();
    }
  }

  public void onRunSafetyNet(View view) {
    safetyNetHelper = SafetyNetHelper.with(this)
        .setApiKey(apiKey.getText().toString()) // https://developer.android.com/training/safetynet/index.html
        .addSafetyNetListener(new SafetyNetHelper.SafetyNetListener() {

          @Override public void onError(@SafetyNetHelper.SafetyNetErrorCode int errorCode, String reason) {
            Spanned html = new HtmlBuilder().font(Color.RED, "ERROR: ").append(reason).toSpan();
            resultText.setText(html);
          }

          @Override public void onFinished(SafetyNetHelper.SafetyNetResponse response,
                                           SafetyNetHelper.SafetyNetVerification verification) {
            HtmlBuilder hb = new HtmlBuilder().p();
            if (response.ctsProfileMatch) {
              hb.font(Color.GREEN, "This device passed the Android compatibility test.").close();
            } else {
              hb.font(Color.RED, "This device did not pass the Android compatibility test.").close();
            }
            if (!verification.isValid()) {
              hb.strong("The response failed verification.");
            }
            Spanned html = hb.toSpan();
            resultText.setText(html);
          }
        })
        .run();
  }

}
