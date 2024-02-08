package com.a4455jkjh.apktool.util;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Environment;
import android.preference.PreferenceManager;

import androidx.core.content.ContextCompat;
import androidx.core.content.res.ResourcesCompat;

import com.a4455jkjh.apktool.ApktoolApplication;
import com.a4455jkjh.apktool.R;
import com.a4455jkjh.apktool.fragment.files.FileComparator;
import com.a4455jkjh.apktool.lexer.Packages;
import com.a4455jkjh.apktool.service.NotificationManager;
import com.a4455jkjh.apktool.service.Project;

import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import brut.androlib.ApkOptions;
import sun1.security.pkcs.PKCS8Key;

public class Settings {
    public static boolean lightTheme;
    public static boolean isThemeChanged;
    public static String aapt;
    public static String framework_dir;
    public static PrivateKey privateKey;
    public static X509Certificate certificate;
    public static Typeface typeface;
    public static int fontSize;
    public static boolean isFontSizeChanged;
    public static boolean mBakDeb;
    public static String projectPath;
    public static Project project;
    public static String output_directory;
    public static boolean analysis_all_smali;

    /**
     * Initialize the application.
     *
     * @param application the ApktoolApplication instance
     */
    public static void init(ApktoolApplication application) {
        lightTheme = true;
        fontSize = 14;
        NotificationManager nm = new NotificationManager(application);
        project = new Project(nm, ContextCompat.getNoBackupFilesDir(application));
        typeface = ResourcesCompat.getFont(application, R.font.monospace);
        AssetManager assets = application.getAssets();
        File filesDir = getRootDirPath(application);
        copyFiles(assets, filesDir);
        loadSettings(application);
        ApkOptions o = ApkOptions.INSTANCE;
        o.aaptPath = aapt;
        o.aaptVersion = 1;
        o.frameworkFolderLocation = framework_dir;
        isThemeChanged = false;
        isFontSizeChanged = false;
    }

    /**
     * Get the root directory path.
     *
     * @param context the Context instance
     * @return the root directory path
     */
    public static File getRootDirPath(Context context) {
        if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())) {
            return ContextCompat.getExternalFilesDirs(context.getApplicationContext(), null)[0];
        } else {
            return context.getApplicationContext().getFilesDir();
        }
    }

    /**
     * Load settings from shared preferences.
     *
     * @param context The context to access shared preferences.
     */
    public static void loadSettings(Context context) {
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(context);
        loadApplicationSettings(sp);
        loadEditorSettings(sp);
        loadApkOptions(sp);
        int defaultCompator = sp.getInt("defaultCompator", 0);
        FileComparator.setDefaultAdapter(defaultCompator);
    }

    /**
     * Load editor settings from shared preferences.
     *
     * @param sp Shared preferences object.
     */
    private static void loadEditorSettings(SharedPreferences sp) {
        String fontSize = sp.getString("font_size", "");
        int size;

        // Check if font size is empty
        if (fontSize.length() == 0) {
            size = 14;
        } else {
            size = Integer.parseInt(fontSize); // Parse font size from string
        }

        // Check if font size has changed
        if (Settings.fontSize != size) {
            isFontSizeChanged = true;
        }
        Settings.fontSize = size;
    }

    /**
     * Load application settings from shared preferences.
     *
     * @param sp Shared preferences object.
     */
    private static void loadApplicationSettings(SharedPreferences sp) {
        boolean lightTheme = sp.getBoolean("light_theme", true);
        if (lightTheme != Settings.lightTheme) isThemeChanged = true;
        Settings.lightTheme = lightTheme;

        // Check if project path is null
        if (Settings.projectPath == null) {
            projectPath = sp.getString("projectPath", "");
            project.setProjectPath(projectPath);
        }
    }

    public static void setProjectPath(String projectPath, Context ctx) {
        Settings.projectPath = projectPath;
        project.setProjectPath(projectPath);
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(ctx);
        SharedPreferences.Editor e = sp.edit();
        e.putString("projectPath", projectPath);
        e.apply();
    }

    /**
     * Copies files from the asset manager to the specified output directory.
     *
     * @param assets The asset manager to copy files from.
     * @param outDir The output directory to copy files to.
     */
    private static void copyFiles(AssetManager assets, File outDir) {
        try {
            // Copy aapt binary to output directory
            copy_aapt(assets, outDir);

            // Copy framework files to output directory
            copy_framework(assets, outDir);

            // Load key from assets
            loadKey(assets);

            // Load dex files from assets
            Packages.loadDex(assets);
        } catch (IOException ignored) {
            // Ignore IOException
        } catch (InvalidKeyException | CertificateException ignored) {
            // Ignore InvalidKeyException and CertificateException
        }
    }


    /**
     * Loads the key from the asset manager.
     *
     * @param assets The asset manager to load the key from.
     * @throws IOException          if an I/O error occurs.
     * @throws InvalidKeyException  if the key is invalid.
     * @throws CertificateException if a certificate error occurs.
     */
    private static void loadKey(AssetManager assets) throws IOException, InvalidKeyException, CertificateException {
        loadPrivateKey(assets); // Load private key from assets
        loadCert(assets);       // Load certificate from assets
    }

    /**
     * Loads the certificate from the asset manager.
     *
     * @param assets The asset manager to load the certificate from.
     * @throws IOException          if an I/O error occurs.
     * @throws CertificateException if a certificate error occurs.
     */
    private static void loadCert(AssetManager assets) throws IOException, CertificateException {
        InputStream cert = assets.open("key/testkey.x509.pem");
        certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(cert);
        cert.close();
    }

    /**
     * Loads the private key from the asset manager.
     *
     * @param assets The asset manager to load the private key from.
     * @throws IOException         if an I/O error occurs.
     * @throws InvalidKeyException if the private key is invalid.
     */
    private static void loadPrivateKey(AssetManager assets) throws IOException, InvalidKeyException {
        InputStream key = assets.open("key/testkey.pk8");
        PKCS8Key pkcs8 = new PKCS8Key();
        pkcs8.decode(key);
        privateKey = pkcs8;
        key.close();
    }

    /**
     * Copies the framework jar file from the assets directory to the specified output directory.
     *
     * @param assets the AssetManager object to access the assets directory
     * @param outDir the File object representing the output directory
     * @throws IOException if an I/O error occurs while copying the framework jar file
     */
    private static void copy_framework(AssetManager assets, File outDir) throws IOException {
        InputStream framework_in = assets.open("framework-28.jar");
        File framework = new File(outDir, "framework/1.apk");
        File dir = framework.getParentFile();
        dir.mkdirs();
        OutputStream framework_out = new FileOutputStream(framework);
        IOUtils.copy(framework_in, framework_out);
        framework_in.close();
        framework_out.close();
        framework_dir = dir.getAbsolutePath();
    }

    /**
     * Copies the aapt binary from the assets folder to the specified output directory.
     *
     * @param assets The AssetManager object to access the aapt binary.
     * @param outDir The File object representing the output directory.
     * @throws IOException If an I/O error occurs while copying the aapt binary.
     */
    @SuppressLint("SuspiciousIndentation")
    private static void copy_aapt(AssetManager assets, File outDir) throws IOException {
        String arch;

        if (Build.VERSION.SDK_INT < 28) {
            arch = Build.CPU_ABI;
        } else if (Build.SUPPORTED_32_BIT_ABIS.length > 0) {
            arch = Build.SUPPORTED_32_BIT_ABIS[0];
        } else {
            arch = Build.SUPPORTED_64_BIT_ABIS[0]; // Fix: arch is not available for the x64 device.
        }

        if (arch.startsWith("arm")) {
            arch = "arm";
        } else if (arch.startsWith("x86")) {
            arch = "x86";
        }

        File aapt = new File(outDir, "aapt");
        InputStream aapt_in = assets.open(arch + "/aapt");
        OutputStream aapt_out = new FileOutputStream(aapt);
        IOUtils.copy(aapt_in, aapt_out);
        aapt_in.close();
        aapt_out.close();
        aapt.setExecutable(true);
        Settings.aapt = aapt.getAbsolutePath();
    }

    /**
     * Load the APK options from shared preferences.
     *
     * @param sp The shared preferences object.
     */
    private static void loadApkOptions(SharedPreferences sp) {
        ApkOptions o = ApkOptions.INSTANCE;
        mBakDeb = sp.getBoolean("mBakDeb", true);
        o.copyOriginalFiles = sp.getBoolean("copyOriginalFiles", false);
        o.debugMode = sp.getBoolean("debug_mode", false);
        o.verbose = sp.getBoolean("verbose_mode", false);
        analysis_all_smali = sp.getBoolean("analysis_all_smali", false);
        String output_directory = sp.getString("output_directory", "");

        if (output_directory != null && output_directory.equals("")) {
            output_directory = null;
        }

        Settings.output_directory = output_directory;
    }

    /**
     * Set the output directory for the APK options.
     *
     * @param output_directory The new output directory.
     * @param ctx              The context.
     */
    public static void setOutputDirectory(String output_directory, Context ctx) {
        Settings.output_directory = output_directory;
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(ctx);
        SharedPreferences.Editor e = sp.edit();
        e.putString("output_directory", output_directory);
        e.apply();
    }

}
