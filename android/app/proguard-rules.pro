# Keep UniFFI bindings and JNA (reflection-based native binding).
-keep class uniffi.** { *; }
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
