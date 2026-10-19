# Application-Aware Traceroute (`prectrace`)

Most traceroute/ping tools work around the network layer, like `arping` (L2) and `(tc|ud|)ping`/`trace*` (L3/L3.5).
That's reasonable, but less fun.
Such traces are more likely to be dropped or deprioritized by middleboxes.
Application-aware traces also reveils more information about the internet.
For example, DNS responses can be used to simultaneously extract regional resolution properties using names on split-horizon NS.
NTP can help detect/measure asymmetric delay/jitterm, which might be useful when one is on satellite or DSL links.

Here we present an application-aware traceroute, designed for making stable measurements of the internet.

The program currently supports DNS and NTP traces, in addition to the good old ICMP[46] traceroutes.

> [!WARNING]
>
> Flooding a DNS or NTP server may be considered DoS and
> get you into administrative or legal trouble.
> Traceroute itself also stresses all intermediate routers.
>
> Please only target your own servers or obtain appropriate
> permission from the server owners, and follow their rate limits.
