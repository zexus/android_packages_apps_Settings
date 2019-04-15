package com.android.settings.crack;

import android.os.SystemProperties;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;

import dalvik.system.DexClassLoader;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

public class DexHook implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(final LoadPackageParam lp) {
        final String packageName = SystemProperties.get("security.sysctl.package", "default");

        if (lp.packageName.equals(packageName)) {
            findAndHookMethod(ClassLoader.class, "loadClass", String.class, Boolean.TYPE, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    ClassLoader loader = (ClassLoader) param.thisObject;
                    if (param.hasThrowable()
                            || loader == DexClassLoader.class.getClassLoader()
                            || loader == ClassLoader.getSystemClassLoader()
                            || loader.getParent() == ClassLoader.getSystemClassLoader()) {
                        return;
                    }

                    Class<?> clazz = (Class<?>) param.getResult();
                    Object dex = XposedHelpers.callMethod(clazz, "getDex");
                    byte[] data = (byte[]) XposedHelpers.callMethod(dex, "getBytes");

                    File file = new File("/data/data/" + packageName + "/",
                            packageName + "_" + data.length + "_dumpdex.dex");
                    if (!file.exists() && file.createNewFile()) {
                        file.setReadable(true, false);
                        WriteThread.write(data, file);
                    }
                }
            });
        }
    }

    static class WriteThread implements Runnable {
        private final byte[] data;
        private final File file;

        private WriteThread(byte[] data, File file) {
            this.data = data;
            this.file = file;
        }

        @Override
        public void run() {
            try (BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(file))) {
                bufferedOutputStream.write(data);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        static void write(final byte[] data, final File file) {
            new Thread(new WriteThread(data, file)).start();
        }
    }
}
