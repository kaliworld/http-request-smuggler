# HTTP Request Smuggler

This Burp Suite extension automatically detects and exploits [HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling) vulnerabilities using advanced desynchronization techniques developed by PortSwigger researcher James Kettle. It supports comprehensive scanning for HTTP/1.1 and HTTP/2-downgrade desync vulnerabilities, client-side desyncs, and connection state attacks.

Version 3.0 landed in 2025 and adds parser discrepancy detection, which bypasses widespread desync defences and makes it significantly more effective. For further information on this, refer to the whitepaper [HTTP/1.1 Must Die: The Desync Endgame](https://portswigger.net/research/http1-must-die).

It's fully compatible with Burp Suite DAST, Professional, and Community editions. Pro and Community editions have a "research mode" for exploring novel techniques, and the DAST integration is useful if you want recurring scans to flag novel threats as soon as they're released.

### Features
- Detection based on root-cause detection of underlying parsing discrepancies, which is significantly more reliable and resistant to target-specific quirks.
- Many permutation techniques for bypassing different server configurations
- HTTP/1.1 CL.TE and TE.CL desync detection with timeout-based confirmation
- HTTP/2 request smuggling including tunneling and header injection attacks
- Client-side desync detection for browser-powered attacks
- Header smuggling and removal vulnerability detection
- Connection state manipulation and pause-based desync techniques
- Automated exploit generation with Turbo Intruder integration
- False positive reduction through multiple validation techniques


### Install
The easiest way to install this is in Burp Suite, via `Extender -> BApp Store`.

If you prefer to load the jar manually, in Burp Suite (community or pro), use `Extender -> Extensions -> Add` to load `build/libs/http-request-smuggler-all.jar`

### Compile
[Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) is a dependency of this project, add it to the root of this source tree as `turbo-intruder-all.jar`

Build using:

Linux: `./gradlew build fatjar`

Windows: `gradlew.bat build fatjar`

Grab the output from `build/libs/desynchronize-all.jar`

### Go scanning component

The extension now packages a small, local Go scanning service (`smugglerd`). The
Java classes remain the Burp/JVM adapter and continue to provide the legacy
scanner as a compatibility fallback while individual scan types are migrated.
The default build embeds the current platform; release builds can use, for
example, `./gradlew -PgoPlatforms=linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64 fatJar`.

At load time the adapter selects the matching binary, extracts it into a private
temporary directory, verifies its packaged SHA-256 digest, and starts it. Linux
and macOS use a mode-0600 Unix socket. Windows uses a numeric loopback TCP
listener. The service refuses non-loopback TCP binds, requires a random bearer
token, accepts only versioned `scan` and `mutate` operations, and limits request
size, concurrency and execution time. It never listens on an external interface.
The child is stopped and its temporary directory removed when the extension is
unloaded. If the current OS/architecture was not packaged, startup fails safely
and the existing Java scanner remains available.

Troubleshooting: check the extension output for startup errors, verify that the
temporary directory is executable, and rebuild for the exact `GOOS/GOARCH`.
Endpoint security products may prevent execution from a temporary directory.
Do not expose the IPC socket or bearer token, and scan only authorized targets.

### Standalone command-line scanner

GitHub Releases include a `smuggler` executable for Linux, macOS, and Windows.
It is a separate static Go command: it does not require Burp, `smugglerd`, a JVM,
or third-party Go modules. Put one authorized `http://` or `https://` target on
each line of `url.txt` (blank lines and lines beginning with `#` are ignored),
then run:

```shell
smuggler -input url.txt -concurrency 4 -timeout 10s
```

By default, only targets with a potential vulnerability are written to the
JSON Lines report `comeout.txt`; clean targets and connection failures are not
written. Results are streamed so large lists do not have to be retained in
memory. Use `-all` to include every target, `-input -` or `-output -` for
stdin/stdout, and use `-techniques` with a comma-separated technique list to
override the conservative defaults.
Exit with `Ctrl+C` to cancel outstanding work. A status difference or probe
error is a lead requiring manual confirmation, not proof of a vulnerability.
Never use the batch mode against targets without explicit permission.

Maintainers create a tag such as `v3.2.0` to run the Release workflow. It tests
the Go tree, cross-compiles the standalone CLI and daemon, builds the Java 21
extension with every supported daemon, publishes archives and SHA-256 checksum
files, and creates the GitHub Release automatically. The workflow can also be
started manually for an existing tag.

### Use
Right click on a request and click `Launch Smuggle probe`, then watch the Organizer and extension's output pane under `Extender->Extensions->HTTP Request Smuggler`

If you're using Burp Pro, any findings will also be reported as scan issues.

If you right click on a request that uses chunked encoding, you'll see another option marked `Launch Smuggle attack`. This will open a Turbo Intruder window in which you can try out various attacks by editing the `prefix` variable.

For more advanced use watch the [video](https://portswigger.net/blog/http-desync-attacks).

### Practice

We've released a collection of [free online labs to practise against](https://portswigger.net/web-security/request-smuggling). Here's how to use the tool to solve the first lab - [HTTP request smuggling, basic CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te):

1. Use the Extender->BApp store tab to install the 'HTTP Request Smuggler' extension.
2. Load the lab homepage, find the request in the proxy history, right click and select 'Launch smuggle probe', then click 'OK'.
3. Wait for the probe to complete, indicated by 'Completed 1 of 1' appearing in the extension's output tab.
4. If you're using Burp Suite Pro, find the reported vulnerability in the dashboard and open the first attached request.
5. If you're using Burp Suite Community, copy the request from the output tab and paste it into the repeater, then complete the 'Target' details on the top right.
6. Right click on the request and select 'Smuggle attack (CL.TE)'.
7. Change the value of the 'prefix' variable to 'G', then click 'Attack' and confirm that one response says 'Unrecognised method GPOST'.

By changing the 'prefix' variable in step 7, you can solve all the labs and virtually every real-world scenario.
