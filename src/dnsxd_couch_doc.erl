%% -------------------------------------------------------------------
%%
%% Copyright (c) 2011 Andrew Tunnell-Jones. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------
-module(dnsxd_couch_doc).
-include("dnsxd_couch.hrl").

%% API
-export([encode/1, decode/1, merge/2]).

-define(ERL_REC_TAG, <<"dnsxd_couch_rec">>).

%%%===================================================================
%%% API
%%%===================================================================

encode(Rec) when is_tuple(Rec) ->
    Tag = element(1, Rec),
    PL = [ KV || KV <- lists:zipwith(lzw_fun(Tag), fields(Tag), values(Rec)),
		 KV =/= undefined ],
    {[{?ERL_REC_TAG, atom_to_binary(Tag, latin1)}|PL]}.

decode({List}) when is_list(List) -> decode(List);
decode(List) when is_list(List) ->
    case lists:keyfind(?ERL_REC_TAG, 1, List) of
	{?ERL_REC_TAG, TagBin} ->
	    %% todo: prime atom table so binary_to_existing_atom can be used
	    TagAtom = binary_to_atom(TagBin, latin1),
	    Values = [ decode_value(TagAtom, FieldAtom, List)
		       || FieldAtom <- fields(TagAtom) ],
	    list_to_tuple([TagAtom|Values]);
	false -> List
    end.

merge(#dnsxd_couch_lz{name = ZoneName} = Winner,
      #dnsxd_couch_lz{name = ZoneName} = Loser) ->
    MergeFuns = [ fun merge_enabled/2,
		  fun merge_rr/2,
		  fun merge_axfr_enabled/2,
		  fun merge_axfr_hosts/2,
		  fun merge_tsig_keys/2,
		  fun merge_export_enabled/2,
		  fun merge_history/2,
		  fun merge_soa_param/2 ],
    merge(Winner, Loser, MergeFuns).

%%%===================================================================
%%% Internal functions
%%%===================================================================

decode_value(dnsxd_couch_lz, name, List) ->
    get_value(<<"_id">>, List);
decode_value(dnsxd_couch_lz, rev, List) ->
    get_value(<<"_rev">>, List);
decode_value(dnsxd_couch_tk, secret, List) ->
    base64:decode(get_value(<<"secret">>, List));
decode_value(dnsxd_couch_dk_rsa, Field, List) ->
    FieldBin = atom_to_binary(Field, latin1),
    base64:decode(get_value(FieldBin, List));
decode_value(Tag, Field, List) ->
    Default = get_default(Tag, Field),
    case get_value(atom_to_binary(Field, latin1), List, Default) of
	{MebePL} when is_list(MebePL) ->
	    case get_value(?ERL_REC_TAG, MebePL) of
		undefined -> MebePL;
		_ -> decode(MebePL)
	    end;
	[{MebePL}|_] = MebePLs when is_list(MebePL) ->
	    case get_value(?ERL_REC_TAG, MebePL) of
		undefined -> List;
		_ -> [ decode(PL) || PL <- MebePLs ]
	    end;
	MebeBase64 when Tag =:= dnsxd_couch_rr andalso
			Field =:= data andalso
			is_binary(MebeBase64) ->
	    try base64:decode(MebeBase64)
	    catch _:_ -> MebeBase64 end;
	Value -> Value
    end.

-define(FIELDS(Atom), fields(Atom) -> record_info(fields, Atom)).
?FIELDS(dnsxd_couch_lz);
?FIELDS(dnsxd_couch_ez);
?FIELDS(dnsxd_couch_rr);
?FIELDS(dnsxd_couch_he);
?FIELDS(dnsxd_couch_sp);
?FIELDS(dnsxd_couch_tk);
fields(Tag) -> dns_record_info:fields(Tag).

values(Rec) when is_tuple(Rec) -> tl(tuple_to_list(Rec)).

lzw_fun(dnsxd_couch_lz) -> fun lzw_z_fun/2;
lzw_fun(dnsxd_couch_ez) -> fun lzw_z_fun/2;
lzw_fun(dnsxd_couch_rr) -> fun lzw_rr_fun/2;
lzw_fun(dnsxd_couch_tk) -> fun lzw_tk_fun/2;
lzw_fun(_) -> fun lzw_fun/2.

lzw_z_fun(name, Name) -> {<<"_id">>, Name};
lzw_z_fun(rev, undefined) -> undefined;
lzw_z_fun(rev, Rev) -> {<<"_rev">>, Rev};
lzw_z_fun(rr, RRs) -> {<<"rr">>, [ encode(RR) || RR <- RRs ]};
lzw_z_fun(soa_param, SOAParam) -> {<<"soa_param">>, encode(SOAParam)};
lzw_z_fun(tsig_keys, Keys) ->
    {<<"tsig_keys">>, [ encode(Key) || Key <- Keys ]};
lzw_z_fun(Key, Value) -> lzw_fun(Key, Value).

lzw_rr_fun(data, Bin) when is_binary(Bin) -> {<<"data">>, base64:encode(Bin)};
lzw_rr_fun(data, Data) when is_tuple(Data) -> {<<"data">>, encode(Data)};
lzw_rr_fun(Key, Value) -> lzw_fun(Key, Value).

lzw_tk_fun(secret, Bin) when is_binary(Bin) ->
    {<<"secret">>, base64:encode(Bin)};
lzw_tk_fun(Key, Value) -> lzw_fun(Key, Value).

lzw_fun(history, History) ->
    {<<"history">>, [ encode(Entry) || Entry <- History ]};
lzw_fun(Key, undefined) -> {atom_to_binary(Key, latin1), null};
lzw_fun(Key, Value) -> {atom_to_binary(Key, latin1), Value}.

get_value(Key, List) -> get_value(Key, List, undefined).

get_value(Key, List, Default) ->
    case lists:keyfind(Key, 1, List) of
	{Key, Value} -> Value;
	false -> Default
    end.

get_default(Tag, Field)
  when Tag =:= dnsxd_couch_lz orelse
       Tag =:= dnsxd_couch_ez orelse
       Tag =:= dnsxd_couch_rr orelse
       Tag =:= dnsxd_couch_he orelse
       Tag =:= dnsxd_couch_sp ->
    Fields = fields(Tag),
    [_|Values] = tuple_to_list(defaults(Tag)),
    DefaultPL = lists:zip(Fields, Values),
    get_value(Field, DefaultPL);
get_default(_, _) -> undefined.

-define(DEFAULTS(Atom), defaults(Atom) -> #Atom{}).
?DEFAULTS(dnsxd_couch_lz);
?DEFAULTS(dnsxd_couch_ez);
?DEFAULTS(dnsxd_couch_rr);
?DEFAULTS(dnsxd_couch_he);
?DEFAULTS(dnsxd_couch_sp).

merge(Winner, _Loser, []) -> Winner;
merge(Winner, Loser, [Fun|Funs]) ->
    NewWinner = Fun(Winner, Loser),
    merge(NewWinner, Loser, Funs).

%% simple merges - just go for whichever was set later
merge_enabled(#dnsxd_couch_lz{enabled_set = TW} = Winner,
	#dnsxd_couch_lz{enabled = Enabled, enabled_set = TL}) when TL > TW ->
    Winner#dnsxd_couch_lz{enabled = Enabled};
merge_enabled(#dnsxd_couch_lz{} = Winner, #dnsxd_couch_lz{}) -> Winner.

merge_axfr_enabled(#dnsxd_couch_lz{axfr_enabled_set = TW} = Winner,
	     #dnsxd_couch_lz{axfr_enabled = Enabled, axfr_enabled_set = TL})
  when TL > TW -> Winner#dnsxd_couch_lz{enabled = Enabled};
merge_axfr_enabled(#dnsxd_couch_lz{} = Winner, #dnsxd_couch_lz{}) -> Winner.

merge_export_enabled(#dnsxd_couch_lz{export_set = TW} = Winner,
	       #dnsxd_couch_lz{export = Enabled, export_set = TL})
  when TL > TW -> Winner#dnsxd_couch_lz{export = Enabled};
merge_export_enabled(#dnsxd_couch_lz{} = Winner, #dnsxd_couch_lz{}) -> Winner.

merge_soa_param(#dnsxd_couch_lz{soa_param_set = TW} = Winner,
	  #dnsxd_couch_lz{soa_param = SOAParam, soa_param_set = TL})
  when TL > TW -> Winner#dnsxd_couch_lz{soa_param = SOAParam};
merge_soa_param(#dnsxd_couch_lz{} = Winner, #dnsxd_couch_lz{}) -> Winner.

%% messier merges

%% rr
merge_rr(#dnsxd_couch_lz{rr = WRRs} = Winner, #dnsxd_couch_lz{rr = LRRs}) ->
    %% todo: check for invalid rrsets (multiple cname at same dname, etc)
    CombinedRRs = dnsxd_lib:unique(WRRs ++ LRRs),
    NewRRs = dedupe_tuples(#dnsxd_couch_rr.id,
			   #dnsxd_couch_rr.set,
			   CombinedRRs),
    Winner#dnsxd_couch_lz{rr = NewRRs}.

%% keeping the common hosts is probably preferable
merge_axfr_hosts(#dnsxd_couch_lz{axfr_hosts = HW} = Winner,
		 #dnsxd_couch_lz{axfr_hosts = HL}) ->
    Hosts = sets:to_list(sets:intersection(sets:from_list(HW),
					   sets:from_list(HL))),
    Winner#dnsxd_couch_lz{axfr_hosts = Hosts}.

%% tsig_keys
merge_tsig_keys(#dnsxd_couch_lz{tsig_keys = WKeys} = Winner,
	  #dnsxd_couch_lz{tsig_keys = LKeys}) ->
    CombinedKeys = dnsxd_lib:unique(WKeys ++ LKeys),
    NewKeys = dedupe_tuples(#dnsxd_couch_tk.id,
			    #dnsxd_couch_tk.set,
			    CombinedKeys),
    Winner#dnsxd_couch_lz{tsig_keys = NewKeys}.

%% history
merge_history(#dnsxd_couch_lz{history = WHistory} = Winner,
	#dnsxd_couch_lz{history = LHistory}) ->
    Combined = dnsxd_lib:unique(WHistory ++ LHistory),
    %% todo: add merge note
    Winner#dnsxd_couch_lz{history = Combined}.

%% helpers

dedupe_tuples(TagPos, TimePos, Tuples) ->
    DupeTags = find_dupe_tupletag(TagPos, Tuples),
    Fun = fun(Tuple) ->
		  Tag = element(TagPos, Tuple),
		  lists:member(Tag, DupeTags)
	  end,
    {DupeTuples, SingleTuples} = lists:partition(Fun, Tuples),
    DedupedTuples = pick_tuples(TagPos, TimePos, DupeTuples),
    lists:sort(DedupedTuples ++ SingleTuples).

pick_tuples(TagPos, TimePos, DupeTuples) ->
    pick_tuples(TagPos, TimePos, DupeTuples, []).

pick_tuples(_TagPos, _TimePos, [], Deduped) -> Deduped;
pick_tuples(TagPos, TimePos, [Tuple|Tuples], Deduped) ->
    Tag = element(TagPos, Tuple),
    case lists:keytake(Tag, TagPos, Tuples) of
	{value, DupeTuple, Tuples0} ->
	    NewTuple = pick_tuple(TimePos, Tuple, DupeTuple),
	    NewTuples = [NewTuple|Tuples0],
	    pick_tuples(TagPos, TimePos, NewTuples, Deduped);
	false ->
	    NewDeduped = [Tuple|Deduped],
	    pick_tuples(TagPos, TimePos, Tuples, NewDeduped)
    end.

pick_tuple(TimePos, A, B) ->
    if element(TimePos, A) < element(TimePos, B) -> B;
       true -> A end.

find_dupe_tupletag(TagPos, Tuples) ->
    find_dupe_tupletag(TagPos, Tuples, dict:new()).

find_dupe_tupletag(_TagPos, [], Dict) ->
    [ Tag || {Tag, Count} <- dict:to_list(Dict), Count > 1 ];
find_dupe_tupletag(TagPos, [Tuple|Tuples], Dict) ->
    Tag = element(TagPos, Tuple),
    NewDict = dict:update_counter(Tag, 1, Dict),
    find_dupe_tupletag(TagPos, Tuples, NewDict).
