# SafetyNetHelper <a target="_blank" href="https://twitter.com/jrummyapps"><img src="https://img.shields.io/twitter/follow/jrummyapps.svg?style=social" /></a>
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

# Download

<a target="_blank" href="https://developer.android.com/reference/android/os/Build.VERSION_CODES.html#HONEYCOMB"><img src="https://img.shields.io/badge/API-11%2B-blue.svg?style=flat" alt="API" /></a>
  <a target="_blank" href="LICENSE.txt"><img src="http://img.shields.io/:license-apache-blue.svg" alt="License" /></a>
  <a target="_blank" href="https://maven-badges.herokuapp.com/maven-central/com.jrummyapps/safetynethelper"><img src="https://maven-badges.herokuapp.com/maven-central/com.jrummyapps/safetynethelper/badge.svg" alt="Maven Central" /></a>

Add the dependency to your app level build.gradle file:

```groovy
compile 'com.jrummyapps:safetynethelper:{latest-version}'
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
