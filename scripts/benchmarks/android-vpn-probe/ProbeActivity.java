package dev.yuhaiin.stackprobe;

import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import android.util.Log;
import java.io.*;
import java.net.*;
import java.util.*;
import org.json.*;

/** Isolated platform fixture. Its only VPN route is the reserved test subnet. */
public class ProbeActivity extends Activity {
    private void launch() {
        Intent service = new Intent(this, TunnelService.class);
        service.putExtra("mtu", getIntent().getIntExtra("mtu", 1500));
        startForegroundService(service);
        finish();
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        Intent consent = VpnService.prepare(this);
        if (consent == null) launch();
        else startActivityForResult(consent, 1);
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 1 && result == RESULT_OK) launch();
        else finish();
    }

    public static class TunnelService extends VpnService {
        private ParcelFileDescriptor vpn;
        private java.lang.Process child;
        private Network testNetwork;
        @Override public int onStartCommand(Intent intent, int flags, int id) {
            NotificationManager nm = getSystemService(NotificationManager.class);
            nm.createNotificationChannel(new NotificationChannel("probe", "Stack probe", NotificationManager.IMPORTANCE_LOW));
            startForeground(1, new Notification.Builder(this, "probe")
                .setContentTitle("Testing lightweight TCP")
                .setSmallIcon(android.R.drawable.stat_sys_warning).build());
            int mtu = intent.getIntExtra("mtu", 1500);
            new Thread(new Runnable() {
                @Override public void run() { runProbe(mtu); }
            }, "vpn-probe").start();
            return START_NOT_STICKY;
        }
        private void runProbe(int mtu) {
            JSONObject out = new JSONObject();
            LocalServerSocket transfer = null;
            try {
                out.put("mtu", mtu).put("api", Build.VERSION.SDK_INT)
                    .put("fingerprint", Build.FINGERPRINT).put("uid", android.os.Process.myUid());
                vpn = new Builder().setSession("Yuhaiin isolated stack probe").setMtu(mtu)
                    .addAddress("198.18.0.1", 24).addRoute("198.18.0.0", 24)
                    .addAllowedApplication(getPackageName()).establish();
                if (vpn == null) throw new IOException("VPN permission not granted");
                String name = "yuhaiin-stackprobe-" + android.os.Process.myPid();
                transfer = new LocalServerSocket(name);
                File log = new File(getFilesDir(), "native-" + mtu + ".log");
                child = new ProcessBuilder(getApplicationInfo().nativeLibraryDir + "/libstackprobe.so",
                    "-mode=android-stack", "-mtu=" + mtu, "-vpn-socket=" + name)
                    .redirectErrorStream(true).redirectOutput(log).start();
                try (LocalSocket peer = transfer.accept()) {
                    peer.setFileDescriptorsForSend(new FileDescriptor[]{vpn.getFileDescriptor()});
                    peer.getOutputStream().write(1);
                    peer.getOutputStream().flush();
                }
                transfer.close();
                transfer = null;
                boolean ready = false;
                for (int i = 0; i < 200; i++) {
                    if (new String(java.nio.file.Files.readAllBytes(log.toPath())).contains("READY")) {
                        ready = true;
                        break;
                    }
                    Thread.sleep(25);
                }
                if (!ready) throw new IOException("native stack not ready: " + new String(java.nio.file.Files.readAllBytes(log.toPath())));
                // establish() returning does not guarantee that app default
                // network selection has caught up. Bind this test's sockets to
                // the exact VPN Network, rather than benchmarking an underlay.
                ConnectivityManager cm = getSystemService(ConnectivityManager.class);
                for (int attempt = 0; attempt < 200 && testNetwork == null; attempt++) {
                    for (Network network : cm.getAllNetworks()) {
                        NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                        LinkProperties link = cm.getLinkProperties(network);
                        if (caps == null || link == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                        for (LinkAddress address : link.getLinkAddresses()) {
                            if (address.getAddress().getHostAddress().equals("198.18.0.1")) testNetwork = network;
                        }
                    }
                    if (testNetwork == null) Thread.sleep(25);
                }
                if (testNetwork == null) throw new IOException("test VPN Network did not become available");
                out.put("vpn_network", testNetwork.toString());
                // Warm the Java generator and native stack before timed samples.
                transfer(0, 0, 16L * 1024 * 1024);
                transfer(1, 0, 16L * 1024 * 1024);
                JSONArray samples = new JSONArray();
                for (int sample = 1; sample <= 3; sample++) {
                    for (int direction = 0; direction < 2; direction++) {
                        samples.put(transfer(direction, sample, 256L * 1024 * 1024));
                    }
                }
                out.put("samples", samples).put("ok", true);
            } catch (Exception e) {
                Log.e("YuhaiinStackProbe", "probe failed", e);
                try { out.put("ok", false).put("error", e.toString()); } catch (Exception ignored) {}
            } finally {
                if (child != null) child.destroy();
                try { if (vpn != null) vpn.close(); } catch (IOException ignored) {}
                try { if (transfer != null) transfer.close(); } catch (IOException ignored) {}
                try (FileWriter file = new FileWriter(new File(getFilesDir(), "result-" + mtu + ".json"))) {
                    file.write(out.toString(2));
                } catch (Exception e) { Log.e("YuhaiinStackProbe", "save failed", e); }
                stopSelf();
            }
        }
        private JSONObject transfer(int direction, int sample, long size) throws Exception {
            byte[] buf = new byte[65536];
            Arrays.fill(buf, (byte)0xa5);
            try (Socket socket = testNetwork.getSocketFactory().createSocket()) {
                socket.connect(new InetSocketAddress("198.18.0.2", 5201), 10000);
                socket.setSoTimeout(30000);
                DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                DataInputStream input = new DataInputStream(socket.getInputStream());
                long start = System.nanoTime();
                output.writeByte(direction);
                output.writeLong(size);
                for (long left = size; left > 0;) {
                    int n = (int)Math.min(left, buf.length);
                    if (direction == 0) output.write(buf, 0, n);
                    else {
                        input.readFully(buf, 0, n);
                        for (int i = 0; i < n; i++) if (buf[i] != (byte)0xa5) throw new IOException("payload mismatch");
                    }
                    left -= n;
                }
                if (input.readUnsignedByte() != 1) throw new IOException("missing verified completion");
                long elapsed = System.nanoTime() - start;
                return new JSONObject().put("sample", sample).put("direction", direction == 0 ? "upload" : "download")
                    .put("bytes", size).put("elapsed_ns", elapsed).put("mbps", size * 8000.0 / elapsed);
            }
        }
        @Override public void onDestroy() {
            if (child != null) child.destroy();
            try { if (vpn != null) vpn.close(); } catch (IOException ignored) {}
            super.onDestroy();
        }
    }
}
