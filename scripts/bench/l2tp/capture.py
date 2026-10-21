"""Bounded, header-only CI packet captures for L2TP interoperability tests.

Captures run on the GitHub Linux host (not inside the minimal Docker images).
The outer UDP capture includes only SLL2 + IPv4 + UDP headers (snaplen 48): PPP
authentication data and L2TP payload are never written to that pcap.
The server TCP capture uses snaplen 128, so it includes TCP options but MAY
include a short prefix of synthetic echo test payload.
"""
from contextlib import contextmanager
from pathlib import Path
import os
import signal
import subprocess
import time


class Capture:
    def __init__(self, path: Path, command: list[str]):
        self.path = path
        self.log_path = path.with_name(path.name + ".tcpdump.log")
        self.command = command
        self.process = None

    def start(self):
        with self.log_path.open("w") as log:
            self.process = subprocess.Popen(
                self.command, stdout=subprocess.DEVNULL, stderr=log,
            )
        # tcpdump prints "listening on ..." after opening the capture device.
        # Do not silently miss the beginning of the test or report empty pcaps.
        for _ in range(60):
            if self.process.poll() is not None:
                break
            if "listening on " in self.log_path.read_text(errors="replace"):
                return
            time.sleep(0.05)
        self.stop()
        raise RuntimeError(
            f"tcpdump did not start for {self.path}: "
            + self.log_path.read_text(errors="replace")
        )

    def stop(self):
        if self.process is None or self.process.poll() is not None:
            return
        self.process.send_signal(signal.SIGINT)
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def discard(self):
        # tcpdump's -C/-W ring appends a numeric suffix to rotated files.
        for path in self.path.parent.glob(self.path.name + "*"):
            path.unlink(missing_ok=True)


@contextmanager
def capture_diagnostics(runtime, server_container, gateway, directory, label):
    """Keep bounded pcaps on a failed test only; never capture PPP credentials."""
    if directory is None or os.getenv("L2TP_CAPTURE_PCAP") != "1":
        yield
        return

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    slug = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
    pid = subprocess.run(
        [runtime, "inspect", "--format", "{{.State.Pid}}", server_container],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if not pid.isdecimal() or int(pid) <= 0:
        raise RuntimeError(f"invalid container network namespace pid: {pid!r}")
    port = gateway.rsplit(":", 1)[-1]
    if not port.isdecimal() or not 0 < int(port) <= 65535:
        raise RuntimeError(f"invalid mapped UDP port: {gateway!r}")

    # Drop privileges to the runner *after* opening the capture device, so the
    # resulting files can be read by actions/upload-artifact without chown.
    user = os.environ.get("USER", "runner")
    common = ["-Z", user, "-n", "-U", "-C", "4", "-W", "2"]
    tcp = directory / (slug + "-server-tcp.pcap")
    udp = directory / (slug + "-outer-udp-headers.pcap")
    server_udp = directory / (slug + "-server-udp-headers.pcap")
    captures = [
        Capture(tcp, [
            "sudo", "-n", "nsenter", "--target", pid, "--net", "--",
            "tcpdump", "-i", "any", "-s", "128", *common,
            "-w", str(tcp), "tcp", "port", "19991",
        ]),
        # The Linux 'any' interface prepends a 20-byte cooked SLL2 header.
        # 20 + IPv4(20) + UDP(8) = 48; 28 loses both IP addresses and ports.
        Capture(udp, [
            "sudo", "-n", "tcpdump", "-i", "any", "-s", "48", *common,
            "-w", str(udp), "ip", "and", "udp", "and",
            "(", "port", "1701", "or", "port", port, ")",
        ]),
        Capture(server_udp, [
            "sudo", "-n", "nsenter", "--target", pid, "--net", "--",
            "tcpdump", "-i", "any", "-s", "48", *common,
            "-w", str(server_udp), "ip", "and", "udp", "and", "port", "1701",
        ]),
    ]

    failed = True
    try:
        for item in captures:
            item.start()
        print(f"tcpdump ready: {slug} TCP echo + outer UDP headers", flush=True)
        yield
        failed = False
    finally:
        # Stop before the upload step, including on exceptions, so each PCAP
        # contains its final headers and tcpdump's drop counters are flushed.
        for item in reversed(captures):
            item.stop()
        if not failed:
            for item in captures:
                item.discard()
        else:
            print(f"preserved bounded pcaps for {slug} in {directory}", flush=True)
