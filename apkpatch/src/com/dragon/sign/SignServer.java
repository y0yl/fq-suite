package com.dragon.sign;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 内置签名服务（APK 改造方案的核心）。
 *
 * 为什么要它：原方案靠 frida attach 进 App 再 RPC 调 NetworkParams.tryAddSecurityFactor。
 * frida 会话是最大的不稳定源（掉线 / 版本漂移 / houdini 下 native 崩溃 / 内存扫描告警）。
 * 把同样的调用编译进 APK 自己，App 就是一个自带签名端口的常驻服务：
 *
 *   host: adb forward tcp:27043 tcp:27043
 *         TCP 发一行 JSON {"url":"...","batch":[{"k":"v"},...]}
 *         收一行 JSON {"ok":true,"h":[{...},...]}
 *
 * 协议（行分隔 JSON，UTF-8）：
 *   请求  {"url": "<url>", "batch": [ {header: value, ...}, ... ]}
 *         {"url": "<url>", "headers": {header: value, ...}}
 *   响应  {"ok": true, "h": [ {"x-argus": "...", ...}, ... ]}
 *         {"ok": false, "err": "<message>"}
 *   探测  {"ping": 1} -> {"ok": true, "pong": 1, "ver": "<versionName>"}
 */
public class SignServer extends Service {
    static final String TAG = "DragonSign";
    static final int PORT = 27043;
    static final String CH = "dragon_sign";

    volatile boolean running = true;
    Thread acceptor;
    Method mSign;
    final Object lock = new Object();
    PowerManager.WakeLock wl;

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            Class<?> np = Class.forName(
                    "com.bytedance.frameworks.baselib.network.http.NetworkParams");
            for (Method m : np.getDeclaredMethods()) {
                if (m.getName().equals("tryAddSecurityFactor")) {
                    m.setAccessible(true);
                    mSign = m;
                }
            }
            Log.i(TAG, "resolved signer=" + mSign);
        } catch (Throwable t) {
            Log.e(TAG, "resolve failed", t);
        }
        try {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "dragon:sign");
            wl.setReferenceCounted(false);
            wl.acquire();
        } catch (Throwable t) {
            Log.w(TAG, "wakelock failed", t);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        foreground();
        if (acceptor == null) {
            acceptor = new Thread(new Runnable() {
                public void run() { acceptLoop(); }
            }, "dragon-sign-accept");
            acceptor.setDaemon(true);
            acceptor.start();
        }
        return START_STICKY;
    }

    void foreground() {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (Build.VERSION.SDK_INT >= 26) {
                NotificationChannel c = new NotificationChannel(CH, "sign", NotificationManager.IMPORTANCE_MIN);
                c.setShowBadge(false);
                nm.createNotificationChannel(c);
            }
            Notification.Builder b = (Build.VERSION.SDK_INT >= 26)
                    ? new Notification.Builder(this, CH) : new Notification.Builder(this);
            b.setContentTitle("sign").setContentText(":27043").setSmallIcon(android.R.drawable.stat_notify_sync);
            startForeground(47043, b.build());
        } catch (Throwable t) {
            Log.w(TAG, "foreground failed", t);
        }
    }

    void acceptLoop() {
        ServerSocket ss = null;
        while (running) {
            try {
                if (ss == null) {
                    ss = new ServerSocket();
                    ss.setReuseAddress(true);
                    ss.bind(new InetSocketAddress("127.0.0.1", PORT), 64);
                    Log.i(TAG, "listening on 127.0.0.1:" + PORT);
                }
                final Socket s = ss.accept();
                s.setTcpNoDelay(true);
                Thread t = new Thread(new Runnable() {
                    public void run() { serve(s); }
                }, "dragon-sign-client");
                t.setDaemon(true);
                t.start();
            } catch (Throwable t) {
                Log.e(TAG, "accept: " + t);
                try { if (ss != null) ss.close(); } catch (Throwable ignored) { }
                ss = null;
                sleep(500);
            }
        }
    }

    void serve(Socket s) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), "UTF-8"), 1 << 16);
            OutputStream out = s.getOutputStream();
            String line;
            while ((line = in.readLine()) != null) {
                if (line.length() == 0) continue;
                String resp;
                try {
                    resp = handle(line);
                } catch (Throwable t) {
                    Log.e(TAG, "handle: " + t);
                    resp = "{\"ok\":false,\"err\":" + JSONObject.quote(String.valueOf(t)) + "}";
                }
                out.write((resp + "\n").getBytes("UTF-8"));
                out.flush();
            }
        } catch (Throwable t) {
            Log.w(TAG, "serve: " + t);
        } finally {
            try { s.close(); } catch (Throwable ignored) { }
        }
    }

    String handle(String line) throws Exception {
        JSONObject req = new JSONObject(line);
        if (req.has("ping")) {
            JSONObject r = new JSONObject();
            r.put("ok", true).put("pong", 1);
            try {
                r.put("ver", getPackageManager().getPackageInfo(getPackageName(), 0).versionName);
            } catch (Throwable ignored) { }
            return r.toString();
        }
        if (mSign == null) throw new IllegalStateException("signer not resolved");
        // ---- 调试端点：把 metasec 的 ctx 指针/callback 对象图吐出来（unidbg 离线化用）
        if (req.has("dumpctx")) {
            return dumpCtx(req.optInt("size", 0x1000), req.optInt("max", 4096)).toString();
        }
        if (req.has("peek")) {                       // {"peek":"0x7f...","size":4096}
            long addr = Long.parseLong(req.getString("peek").replace("0x", ""), 16);
            int n = req.optInt("size", 4096);
            JSONObject r = new JSONObject();
            try {
                byte[] b = readBytes(addr, n);
                r.put("ok", true).put("addr", addr)
                 .put("b64", android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP));
            } catch (Throwable t) {
                r.put("ok", false).put("addr", addr).put("err", String.valueOf(t));
            }
            return r.toString();
        }
        String url = req.getString("url");
        JSONArray batch = req.optJSONArray("batch");
        if (batch == null) {
            batch = new JSONArray();
            batch.put(req.optJSONObject("headers") == null ? new JSONObject() : req.optJSONObject("headers"));
        }
        JSONArray hs = new JSONArray();
        for (int i = 0; i < batch.length(); i++) {
            Map<String, List<String>> m = new LinkedHashMap<String, List<String>>();
            JSONObject h = batch.getJSONObject(i);
            java.util.Iterator<String> it = h.keys();
            while (it.hasNext()) {
                String k = it.next();
                List<String> l = new ArrayList<String>(1);
                l.add(h.getString(k));
                m.put(k, l);
            }
            Object res;
            synchronized (lock) {
                res = mSign.invoke(null, url, m);
            }
            if (!(res instanceof Map)) throw new IllegalStateException("sign returned " + res);
            JSONObject o = new JSONObject();
            for (Object e : ((Map<?, ?>) res).entrySet()) {
                Map.Entry<?, ?> en = (Map.Entry<?, ?>) e;
                Object v = en.getValue();
                String sv;
                if (v instanceof List) {
                    List<?> l = (List<?>) v;
                    sv = l.isEmpty() ? "" : String.valueOf(l.get(0));
                } else {
                    sv = String.valueOf(v);
                }
                o.put(String.valueOf(en.getKey()), sv);
            }
            hs.put(o);
        }
        JSONObject r = new JSONObject();
        r.put("ok", true).put("h", hs).put("n", hs.length());
        return r.toString();
    }

    static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (Throwable ignored) { }
    }

    // ------------------------------------------------------------------ ctx 导出
    // 目的：unidbg 离线签名需要 metasec 的 ctx 结构体。从 PC 侧用 frida 拿不到
    // （类被 dex VMP 装在 NewMiraClassloader 里，Java.use/enumerateClassLoaders 都找不到），
    // 但 App 自己内部用 Class.forName 就能拿到 —— 所以把「读 ctx」这个动作放进 App。

    static Object UNSAFE;
    static Method U_GET_LONG, U_GET_BYTE, U_COPY;

    static Object unsafe() throws Exception {
        if (UNSAFE == null) {
            Class<?> c = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field f = c.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            UNSAFE = f.get(null);
        }
        return UNSAFE;
    }

    static long peekLong(long addr) throws Exception {
        Object u = unsafe();
        if (U_GET_LONG == null) U_GET_LONG = u.getClass().getMethod("getLong", long.class);
        return ((Long) U_GET_LONG.invoke(u, addr)).longValue();
    }

    static byte peekByte(long addr) throws Exception {
        Object u = unsafe();
        if (U_GET_BYTE == null) U_GET_BYTE = u.getClass().getMethod("getByte", long.class);
        return ((Byte) U_GET_BYTE.invoke(u, addr)).byteValue();
    }

    static boolean readable(long addr, int n) {
        try {
            for (int i = 0; i < n; i += 0x100) peekByte(addr + i);
            peekByte(addr + n - 1);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    static byte[] readBytes(long addr, int n) throws Exception {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = peekByte(addr + i);
        return b;
    }

    JSONObject dumpCtx(int size, int cap) throws Exception {
        JSONObject out = new JSONObject();
        JSONArray graph = new JSONArray();
        Class<?> np = Class.forName("com.bytedance.frameworks.baselib.network.http.NetworkParams");
        java.lang.reflect.Field cf = np.getDeclaredField("sAddSecurityFactorProcessCallback");
        cf.setAccessible(true);
        Object cb = cf.get(null);
        if (cb == null) { out.put("ok", false).put("err", "callback null"); return out; }

        // BFS 对象图，收集「像堆指针的 long 值」
        java.util.List<Object> queue = new ArrayList<Object>();
        java.util.List<String> paths = new ArrayList<String>();
        java.util.List<long[]> cands = new ArrayList<long[]>();
        java.util.List<String> candPath = new ArrayList<String>();
        java.util.Set<Object> seen = java.util.Collections.newSetFromMap(
                new java.util.IdentityHashMap<Object, Boolean>());
        queue.add(cb);
        paths.add("cb");
        seen.add(cb);
        int nodes = 0;
        while (!queue.isEmpty() && nodes < 64 && cands.size() < 32) {
            Object o = queue.remove(0);
            String p = paths.remove(0);
            java.lang.reflect.Field[] fs;
            try {
                fs = o.getClass().getDeclaredFields();
            } catch (Throwable t) { continue; }
            JSONObject g = new JSONObject();
            g.put("cls", o.getClass().getName());
            g.put("path", p);
            JSONArray fl = new JSONArray();
            for (java.lang.reflect.Field f : fs) {
                JSONObject fe = new JSONObject();
                try {
                    f.setAccessible(true);
                    Class<?> t = f.getType();
                    fe.put("n", f.getName()).put("t", t.getName());
                    Object v = f.get(o);
                    fe.put("v", v == null ? "null" : String.valueOf(v));
                } catch (Throwable t2) {
                    fe.put("err", String.valueOf(t2));
                }
                fl.put(fe);
            }
            g.put("fields", fl);
            graph.put(g);
            nodes++;
            for (java.lang.reflect.Field f : fs) {
                try {
                    f.setAccessible(true);
                    Class<?> t = f.getType();
                    if (t == long.class || t == int.class) {
                        long v = t == long.class ? f.getLong(o) : (long) f.getInt(o);
                        if (v > 0x10000000L && v < 0x7fffffffffffL && readable(v, 0x100)) {
                            cands.add(new long[]{v});
                            candPath.add(p + "." + f.getName());
                        }
                    } else if (!t.isPrimitive() && t != String.class) {
                        Object v = f.get(o);
                        if (v != null && !seen.contains(v) && seen.size() < 256) {
                            seen.add(v);
                            queue.add(v);
                            paths.add(p + "." + f.getName());
                        }
                    }
                } catch (Throwable ignored) { }
            }
        }

        JSONArray arr = new JSONArray();
        long best = 0;
        for (int i = 0; i < cands.size(); i++) {
            long a = cands.get(i)[0];
            long q0 = 0, q18 = 0, q8 = 0;
            try { q0 = peekLong(a); } catch (Throwable ignored) { }
            try { q8 = peekLong(a + 8); } catch (Throwable ignored) { }
            try { q18 = peekLong(a + 0x18); } catch (Throwable ignored) { }
            JSONObject c = new JSONObject();
            c.put("path", candPath.get(i)).put("addr", a)
             .put("q0", q0).put("q8", q8).put("q18", q18);
            arr.put(c);
            // 判据来自 unidbg 崩溃点：签名路径第一件事是 ldr x21,[ctx,#0x18]，然后 cbz x21
            if (best == 0 && q18 != 0 && readable(a, size)) best = a;
        }
        out.put("ok", true).put("cands", arr).put("n", cands.size()).put("best", best).put("graph", graph);
        if (best != 0) {
            byte[] blob = readBytes(best, size);
            out.put("blob", android.util.Base64.encodeToString(blob, android.util.Base64.NO_WRAP));
        }
        return out;
    }

    @Override
    public void onDestroy() {
        running = false;
        try { if (wl != null && wl.isHeld()) wl.release(); } catch (Throwable ignored) { }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    /** 开机自启 */
    public static class Boot extends BroadcastReceiver {
        @Override
        public void onReceive(Context ctx, Intent i) {
            try {
                ctx.startService(new Intent(ctx, SignServer.class));
                Log.i(TAG, "boot start");
            } catch (Throwable t) {
                Log.e(TAG, "boot: " + t);
            }
        }
    }

    /** 供 adb 直接调用：am broadcast -a com.dragon.sign.START */
    public static class Starter extends BroadcastReceiver {
        @Override
        public void onReceive(Context ctx, Intent i) {
            try {
                ctx.startService(new Intent(ctx, SignServer.class));
                Log.i(TAG, "start via broadcast");
            } catch (Throwable t) {
                Log.e(TAG, "start: " + t);
            }
        }
    }
}