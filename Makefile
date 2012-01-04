.PHONY: all compile rel deps doc clean test
REBAR:=$(shell which rebar || echo ./rebar)
REBAR_URL:="https://github.com/downloads/basho/rebar/rebar"

PLT = dnsxd.plt
APPS = kernel stdlib sasl erts tools runtime_tools crypto public_key asn1

all: deps rel

$(REBAR):
	@echo "No rebar was found so a copy will be downloaded in 5 seconds."
	@echo "Source: ${REBAR_URL} Destination: ${REBAR}"
	@sleep 5
	@echo "Commencing download... "
	@erl -noshell -eval "\
[ application:start(X) || X <- [crypto,public_key,ssl,inets]],\
Request = {\"${REBAR_URL}\", []},\
HttpOpts = [],\
Opts = [{stream, \"$(REBAR)\"}],\
Result = httpc:request(get, Request, HttpOpts, Opts),\
Status = case Result of {ok, _} -> 0; _ -> 1 end,\
init:stop(Status)."
	@chmod u+x ./rebar
	@echo "ok"

compile: $(REBAR)
	@$(REBAR) compile

rel: $(REBAR)
	@$(REBAR) compile generate

deps: $(REBAR)
	@$(REBAR) get-deps

doc: $(REBAR)
	@$(REBAR) doc skip_deps=true

clean: $(REBAR)
	@$(REBAR) clean
	@rm -rf rel/dnsxd

test: $(REBAR)
	@$(REBAR) eunit skip_deps=true

build_plt:
	dialyzer --build_plt --output_plt $(PLT) --apps $(APPS) \
	deps/*/ebin

check_plt:
	dialyzer --check_plt --plt $(PLT) --apps $(APPS)

dialyzer:
	dialyzer --plt $(PLT) dnsxd/ebin