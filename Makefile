.PHONY: all compile rel deps doc clean test

PLT = dnsxd.plt
APPS = kernel stdlib sasl erts tools runtime_tools crypto public_key asn1

all: deps rel

compile:
	@./rebar compile

rel:
	@./rebar compile generate

deps:
	@./rebar get-deps

doc:
	@./rebar doc skip_deps=true

clean:
	@./rebar clean
	@rm -rf rel/dnsxd

test:
	@./rebar eunit skip_deps=true

build_plt:
	dialyzer --build_plt --output_plt $(PLT) --apps $(APPS) \
	deps/*/ebin

check_plt:
	dialyzer --check_plt --plt $(PLT) --apps $(APPS)

dialyzer:
	dialyzer --plt $(PLT) dnsxd/ebin