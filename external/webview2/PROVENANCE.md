# WebView2 SDK provenance

The four vendored SDK files match the files under `build/native/` in the official
[Microsoft.Web.WebView2 1.0.3967.48 NuGet package](https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.3967.48).
Byte comparison and the loader DLL's Microsoft Authenticode signature were checked
on 2026-11-10. This identifies the files; it is not a security certification.

Package download: <https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/1.0.3967.48/microsoft.web.webview2.1.0.3967.48.nupkg>

Package SHA-256: `c66357ac7f324ec9bcafe5241706a023b4122d8c22300c31de4b0eb220db689e`

| File | SHA-256 |
| --- | --- |
| `include/WebView2.h` | `f0d3a67f23492f3bd636114d808feaa408d78e4125b121c730b982e10e00fd80` |
| `include/WebView2EnvironmentOptions.h` | `f9549b9d70400c55faedf0ae61b203028d1711bf73442faab15cff87563a175a` |
| `x64/WebView2Loader.dll` | `bb5fda5f2d3aae5e0977ab28d8a8a00acfd63d73748aaac32daf4fc6645b6677` |
| `x64/WebView2Loader.dll.lib` | `bfc8ccaaa056be95243a5b66a827e5849d2bb39676fca4dcc2053796d8e15c6d` |

[`LICENSE.txt`](LICENSE.txt) and [`NOTICE.txt`](NOTICE.txt) are copied from that
package. The SDK uses Microsoft's BSD-style three-clause license. The separately
installed WebView2 Runtime has its own distribution terms; it is not included in
this directory. Preserve these notices with redistributed SDK files.
