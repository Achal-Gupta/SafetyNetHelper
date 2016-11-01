# SafetyNetHelper
A small library that wraps the Google Play Services SafetyNet API.

# Usage

```java
SafetyNetHelper.with(this)
    .addSafetyNetListener(new SafetyNetHelper.SafetyNetListener() {

      @Override public void onError(int errorCode, String reason) {

      }

      @Override public void onFinished(SafetyNetHelper.SafetyNetResponse response,
                                       SafetyNetHelper.SafetyNetVerification verification) {
        if (response.ctsProfileMatch) {
          // The device passed the Android compatibility test.
        }
      }
    })
    .run();
```

# License

    Copyright (C) 2016, JRummy Apps Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
