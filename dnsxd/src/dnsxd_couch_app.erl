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
-module(dnsxd_couch_app).
-include("dnsxd_couch.hrl").

%% API
-export([install/0]).

-define(DOC_NAME, <<"_design/" ?DNSXD_COUCH_DESIGNDOC>>).

install() ->
    {ok, DbRef} = dnsxd_couch_lib:get_db(),
    Doc = build_doc(DbRef),
    case couchbeam:save_doc(DbRef, Doc) of
	{ok, _} -> ok;
	Other -> Other
    end.

build_doc(DbRef) ->
    BaseProps = [{<<"_id">>, ?DOC_NAME}, {<<"language">>, <<"javascript">>}],
    Props = case couchbeam:open_doc(DbRef, ?DOC_NAME) of
		{ok, {ExistingDocProps}} ->
		    OldRev = lists:keyfind(<<"_rev">>, 1, ExistingDocProps),
		    [OldRev|BaseProps];
		{error, not_found} -> BaseProps
	    end,
    BaseDir = filename:join(code:priv_dir(dnsxd), "couchapp"),
    BaseDirFun = fun(F) -> filename:join(BaseDir, F) end,
    Views = build_views(BaseDirFun("views")),
    Lists = dirs_js_to_obj(BaseDirFun("lists")),
    Filters = dirs_js_to_obj(BaseDirFun("filters")),
    Attachments = build_attachments(BaseDirFun("attachments")),
    OptProps = [{<<"views">>, Views},
		{<<"lists">>, Lists},
		{<<"filters">>, Filters},
		{<<"_attachments">>, Attachments}],
    build_doc(Props, OptProps).

build_doc(Props, []) -> {Props};
build_doc(Props, [{_, {[]}}|OptProps]) -> build_doc(Props, OptProps);
build_doc(Props, [OptProp|OptProps]) -> build_doc([OptProp|Props], OptProps).

build_views(Dir) ->
    {[build_view(Dir, Filename)
      || Filename <- filelib:wildcard("*.map.js", Dir)]}.

build_view(Dir, MapFile) ->
    Name = filename:rootname(filename:rootname(MapFile)),
    ReduceFile = Name ++ ".reduce.js",
    Map = [{<<"map">>, read_file(Dir, MapFile)}],
    View = case filelib:is_file(filename:join(Dir, ReduceFile)) of
	       true -> [{<<"reduce">>, read_file(Dir, ReduceFile)}|Map];
	       false -> Map
	   end,
    {Name, {View}}.

dirs_js_to_obj(Dir) ->
    {[{filename:rootname(Filename), read_file(Dir, Filename)}
      || Filename <- filelib:wildcard("*.js", Dir) ]}.

build_attachments(Dir) ->
    case file:list_dir(Dir) of
	{ok, Filenames} ->
	    Data = fun(File) -> base64:encode(read_file(Dir, File)) end,
	    {[{Filename, {[{<<"content_type">>, content_type(Filename)},
			   {<<"data">>, Data(Filename)}]}}
	      || Filename <- Filenames ]};
	_ -> {[]}
    end.

content_type(Filename) when is_list(Filename) ->
    case string:to_lower(filename:extension(Filename)) of
	".js" -> <<"text/javascript">>;
	".html" -> <<"text/html">>;
	_ -> <<"text/plain">>
    end.

read_file(Dir, Filename) ->
    {ok, Data} = file:read_file(filename:join(Dir, Filename)),
    Data.
