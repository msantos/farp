Poison the ARPs and spoof them too. farp watches the network for ARP
packets and replies with the MAC address of the host it is running on.
This has the effect of sending traffic through your host (if a bridge,
such as herp, is running) or DoS'ing your network if it is not.


# EXPORTS

    start() -> ok
    start(Device, Options) -> {ok, PID}

        Types   Device = string()
                Options = [Opts]
                Opts = {gratuitous, Boolean}
                Boolean = true | false

        Device is the network interface name.

        {gratuitous, true} is the default and will spawn a process to send
        out gratuitous ARP's spoofing your gateway.


# HOW TO USE IT

    > herp:start(). % start up the bridge
    > farp:start().
