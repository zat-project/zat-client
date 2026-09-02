# ============================================================================
# ZAT app — R8/ProGuard rules (release build).
# ============================================================================
# Nearly all keep-rules ride in automatically:
#   - the libbox + meshoprf JNI bridges and the kotlinx-serialization models come
#     from zat-connection-manager's consumerProguardFiles (proguard-rules-zat.pro);
#   - kotlinx-serialization ALSO ships its own package-agnostic R8 rules inside the
#     artifact, so every @Serializable class's serializer is kept regardless of
#     package (covers a future serializable under cloud.zat.app.** too).
# This file therefore holds only app-level concerns.

# Readable crash stack traces from a release APK WITHOUT leaking original source file
# names: keep line numbers (map them back via the R8 mapping.txt in build/outputs) and
# rename the source-file attribute to a constant.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
